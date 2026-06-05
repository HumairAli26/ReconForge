// app.js — ReconForge Frontend Controller v2
// Fixes: MSF status polling, rich console, improved UX

const API = '';   // same-origin
let currentDevices  = [];
let selectedDevice  = null;
let logCount        = 0;
let msfReady        = false;
let msfInstalled    = false;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  startBgCanvas();
  detectSubnet();
  loadModules();
  pollMsfStatus();      // start polling immediately
  log('info', 'ReconForge v1.0 initialised. Checking system status...');
});

// ── Clock ─────────────────────────────────────────────────────────────────────
function startClock() {
  const tick = () => {
    const now = new Date();
    $('sys-time').textContent = now.toTimeString().slice(0,8);
    $('sys-date').textContent = now.toISOString().slice(0,10);
  };
  tick();
  setInterval(tick, 1000);
}

// ── Particle background canvas ────────────────────────────────────────────────
function startBgCanvas() {
  const c = $('bg-canvas');
  if (!c) return;
  const ctx = c.getContext('2d');
  let W, H, particles = [];
  const resize = () => {
    W = c.width  = window.innerWidth;
    H = c.height = window.innerHeight;
  };
  resize();
  window.addEventListener('resize', resize);
  for (let i = 0; i < 60; i++) particles.push({
    x: Math.random()*W, y: Math.random()*H,
    vx: (Math.random()-0.5)*0.3, vy: (Math.random()-0.5)*0.3,
    r: Math.random()*1.5+0.3
  });
  const draw = () => {
    ctx.clearRect(0,0,W,H);
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x<0) p.x=W; if (p.x>W) p.x=0;
      if (p.y<0) p.y=H; if (p.y>H) p.y=0;
      ctx.beginPath();
      ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle='rgba(0,255,157,0.6)'; ctx.fill();
    });
    // draw proximity lines
    for (let i=0;i<particles.length;i++) for (let j=i+1;j<particles.length;j++) {
      const dx=particles[i].x-particles[j].x, dy=particles[i].y-particles[j].y;
      const d=Math.sqrt(dx*dx+dy*dy);
      if (d<130) {
        ctx.beginPath();
        ctx.moveTo(particles[i].x,particles[i].y);
        ctx.lineTo(particles[j].x,particles[j].y);
        ctx.strokeStyle=`rgba(0,255,157,${0.12*(1-d/130)})`;
        ctx.lineWidth=0.5; ctx.stroke();
      }
    }
    requestAnimationFrame(draw);
  };
  draw();
}

// ── Console logger ────────────────────────────────────────────────────────────
function log(type, msg) {
  logCount++;
  $('log-count').textContent = `${logCount} entries`;
  const body = $('console-output');
  const now  = new Date().toTimeString().slice(0,8);

  const prefixes = { ok:'[+]', info:'[*]', warn:'[-]', err:'[!]', dim:'   ' };
  const prefix   = prefixes[type] || '[*]';

  const div = document.createElement('div');
  div.className = 'log-line';
  div.innerHTML = `<span class="log-ts">${now}</span><span class="log-${type}">${prefix} ${escHtml(msg)}</span>`;
  body.appendChild(div);
  body.scrollTop = body.scrollHeight;
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

$('btn-clear').addEventListener('click', () => {
  $('console-output').innerHTML = '';
  logCount = 0; $('log-count').textContent = '0 entries';
});

// ── Activity indicator ────────────────────────────────────────────────────────
function setActivity(label, active=true) {
  $('activity-label').textContent = label;
  document.querySelector('.activity-dot').classList.toggle('active', active);
}

// ── Subnet detect ─────────────────────────────────────────────────────────────
$('btn-detect').addEventListener('click', detectSubnet);
function detectSubnet() {
  fetch(`${API}/api/network/detect`)
    .then(r=>r.json())
    .then(d=>{ $('target-subnet').value=d.network; log('ok',`Auto-detected network: ${d.network}`); })
    .catch(()=>log('warn','Could not auto-detect network.'));
}

// ── Host Discovery ────────────────────────────────────────────────────────────
$('btn-scan-network').addEventListener('click', () => {
  const net = $('target-subnet').value.trim();
  if (!net) return;
  log('info', `Starting ARP/ICMP sweep on: ${net}`);
  setActivity('SCANNING', true);
  $('btn-scan-network').disabled = true;
  $('btn-scan-network').innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> SCANNING...';

  fetch(`${API}/api/scan/network`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ network: net })
  })
  .then(r=>r.json())
  .then(data=>{
    $('btn-scan-network').disabled = false;
    $('btn-scan-network').innerHTML = '<i class="fa-solid fa-radar"></i> DISCOVER HOSTS';
    setActivity('IDLE', false);
    if (data.success) {
      currentDevices = data.devices;
      $('stat-devices').textContent = currentDevices.length;
      log('ok', `Sweep complete — ${currentDevices.length} host(s) found on ${net}`);
      currentDevices.forEach(d=>log('dim', `  ${d.ip.padEnd(16)} ${(d.hostname||'Unknown').padEnd(24)} ${d.vendor||''}`));
      if (typeof updateNetworkTopology === 'function') updateNetworkTopology(currentDevices);
    } else {
      log('err', 'Sweep failed or no hosts found.');
    }
  })
  .catch(e=>{
    $('btn-scan-network').disabled = false;
    $('btn-scan-network').innerHTML = '<i class="fa-solid fa-radar"></i> DISCOVER HOSTS';
    setActivity('ERROR', false);
    log('err', `Sweep error: ${e.message}`);
  });
});

// ── MSF Status — polling approach (fixes always-offline bug) ──────────────────
function pollMsfStatus() {
  const check = () => {
    fetch(`${API}/api/msf/status`)
      .then(r=>r.json())
      .then(updateMsfUI)
      .catch(()=>{});
  };
  check();
  // Poll every 5s so the badge updates as soon as MSF finishes booting
  setInterval(check, 5000);
}

function updateMsfUI(data) {
  const dot    = $('msf-dot');
  const badge  = $('msf-badge');
  const label  = $('msf-label');
  const hint   = $('msf-hint');

  msfInstalled = data.installed;
  const wasReady = msfReady;
  msfReady     = data.available;

  if (msfReady) {
    dot.className   = 'msf-dot ready';
    badge.className = 'msf-badge badge-online';
    badge.textContent = 'ONLINE';
    label.textContent = 'CONNECTED';
    hint.className  = 'msf-hint ok';
    hint.textContent = 'msfconsole process is running and ready';
    if (!wasReady) log('ok', 'Metasploit engine is ONLINE and ready.');
  } else if (msfInstalled) {
    dot.className   = 'msf-dot installing';
    badge.className = 'msf-badge badge-booting';
    badge.textContent = 'BOOTING';
    label.textContent = 'STARTING UP...';
    hint.className  = 'msf-hint';
    hint.textContent = 'msfconsole found — waiting for initialisation (~30-180s)';
  } else {
    dot.className   = 'msf-dot offline';
    badge.className = 'msf-badge badge-offline';
    badge.textContent = 'OFFLINE';
    label.textContent = 'NOT INSTALLED';
    hint.className  = 'msf-hint err';
    hint.textContent = 'msfconsole not found — use --no-msf CLI flag';
    log('warn', 'Metasploit not detected. Modules will run in Python-only mode.');
  }
}

// ── Load modules ──────────────────────────────────────────────────────────────
function loadModules() {
  fetch(`${API}/api/msf/modules`)
    .then(r=>r.json())
    .then(data=>{
      const sel = $('exploit-select');
      sel.innerHTML = '<option value="">— select module —</option>';

      // Group by category
      const cats = {};
      data.modules.forEach(m=>{
        if (!cats[m.category]) cats[m.category] = [];
        cats[m.category].push(m);
      });

      Object.entries(cats).forEach(([cat, mods])=>{
        const grp = document.createElement('optgroup');
        grp.label = cat;
        mods.forEach(m=>{
          const o = document.createElement('option');
          o.value = m.key;
          o.textContent = m.key;
          grp.appendChild(o);
        });
        sel.appendChild(grp);
      });
      log('dim', `${data.modules.length} MSF modules loaded into catalogue.`);
    });
}

// ── Host Details Card ─────────────────────────────────────────────────────────
window.showHostDetails = function(dev) {
  if (!dev || dev.ip === 'Gateway') {
    $('host-card').classList.add('hidden');
    selectedDevice = null;
    $('btn-exploit').disabled = true;
    return;
  }
  selectedDevice = dev;
  $('host-card').classList.remove('hidden');

  $('host-ip').textContent       = dev.ip       || '—';
  $('host-mac').textContent      = dev.mac       || '—';
  $('host-hostname').textContent = dev.hostname  || 'Unknown';
  $('host-vendor').textContent   = dev.vendor    || 'Unknown';
  $('host-type').textContent     = dev.device_type || 'Unknown';

  const risk = dev.risk || 'Clean';
  const rb   = $('host-risk');
  rb.textContent = risk;
  rb.className   = 'risk-badge ' + (
    risk === 'Exploited'  ? 'risk-exploited'  :
    risk === 'Vulnerable' ? 'risk-vulnerable' : 'risk-clean'
  );

  // Ports
  const portsBody = $('ports-body');
  if (dev.open_ports && dev.open_ports.length) {
    portsBody.innerHTML = dev.open_ports.map(p=>{
      const svc = dev.services?.[p]?.service || '?';
      const ban = (dev.services?.[p]?.banner || '').slice(0,40);
      return `<div class="port-row">
        <span class="port-num">${p}</span>
        <span class="port-svc">${escHtml(svc)}</span>
        <span class="port-ban">${escHtml(ban)}</span>
      </div>`;
    }).join('');
  } else {
    portsBody.innerHTML = '<span class="ports-empty">No scan performed yet</span>';
  }

  // Vulns
  const vulnsSection = $('vulns-section');
  const vulnsBody    = $('vulns-body');
  if (dev.vulns && dev.vulns.length) {
    vulnsSection.style.display = 'flex';
    vulnsBody.innerHTML = dev.vulns.map(v=>`
      <div class="vuln-row">
        <span class="vuln-sev sev-${v.severity.toLowerCase()}">${v.severity.toUpperCase()}</span>
        <span class="vuln-name">${escHtml(v.name)}</span>
        <span class="vuln-cve">${escHtml(v.cve||'')}</span>
      </div>`).join('');
  } else {
    vulnsSection.style.display = 'none';
  }

  $('btn-exploit').disabled = false;
};

$('btn-close-card').addEventListener('click', ()=>{
  $('host-card').classList.add('hidden');
  selectedDevice = null;
  $('btn-exploit').disabled = true;
});

// ── Port Scan ─────────────────────────────────────────────────────────────────
$('btn-scan-ports').addEventListener('click', ()=>{
  if (!selectedDevice) return;
  const ip = selectedDevice.ip;
  log('info', `Port & service scan on ${ip}...`);
  setActivity('SCANNING', true);
  $('btn-scan-ports').disabled = true;
  $('btn-scan-ports').innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> SCANNING...';

  fetch(`${API}/api/scan/ports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip })
  })
  .then(r=>r.json())
  .then(data=>{
    $('btn-scan-ports').disabled = false;
    $('btn-scan-ports').innerHTML = '<i class="fa-solid fa-circle-nodes"></i> SCAN PORTS & SERVICES';
    setActivity('IDLE', false);
    if (data.success) {
      const d = data.device;
      const idx = currentDevices.findIndex(x=>x.ip===ip);
      if (idx!==-1) currentDevices[idx] = d; else currentDevices.push(d);
      window.showHostDetails(d);
      if (typeof updateNetworkTopology === 'function') updateNetworkTopology(currentDevices);

      const openCount = (d.open_ports||[]).length;
      const vulnCount = (d.vulns||[]).length;
      log('ok', `Scan complete for ${ip} — ${openCount} open port(s), ${vulnCount} vuln(s) detected`);

      // Refresh stats
      const totalOpen  = currentDevices.reduce((s,x)=>s+(x.open_ports||[]).length, 0);
      const totalVulns = currentDevices.filter(x=>x.vulns&&x.vulns.length).length;
      $('stat-open').textContent  = totalOpen;
      $('stat-vulns').textContent = totalVulns;
    } else {
      log('err', `Port scan failed: ${data.error||'unknown error'}`);
    }
  })
  .catch(e=>{
    $('btn-scan-ports').disabled = false;
    $('btn-scan-ports').innerHTML = '<i class="fa-solid fa-circle-nodes"></i> SCAN PORTS & SERVICES';
    log('err', `Port scan error: ${e.message}`);
  });
});

// ── Exploit / Run Module ──────────────────────────────────────────────────────
$('btn-exploit').addEventListener('click', ()=>{
  const mod = $('exploit-select').value;
  if (!selectedDevice || !mod) {
    log('warn', 'Select a target host and an exploit module first.');
    return;
  }
  const ip = selectedDevice.ip;
  log('info', `Triggering module [${mod}] against ${ip}...`);
  $('btn-exploit').disabled = true;
  $('btn-exploit').innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> RUNNING...';
  setActivity('EXPLOITING', true);

  fetch(`${API}/api/msf/exploit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip, module: mod })
  })
  .then(r=>r.json())
  .then(data=>{
    $('btn-exploit').disabled = false;
    $('btn-exploit').innerHTML = '<i class="fa-solid fa-bolt-lightning"></i> RUN ASSESSMENT';
    setActivity('IDLE', false);

    if (data.success) {
      log('ok', `Module [${mod}] completed against ${ip}`);
      if (data.output) data.output.split('\n').forEach(l=>l.trim()&&log('dim', l));
      const idx = currentDevices.findIndex(x=>x.ip===ip);
      if (idx!==-1) { currentDevices[idx].exploited=true; currentDevices[idx].risk='Exploited'; }
      window.showHostDetails(currentDevices[idx]||selectedDevice);
      if (typeof updateNetworkTopology==='function') updateNetworkTopology(currentDevices);
    } else {
      log('err', `Module failed: ${data.error||'check MSF status'}`);
      if (data.output) log('dim', data.output);
    }
  })
  .catch(e=>{
    $('btn-exploit').disabled = false;
    $('btn-exploit').innerHTML = '<i class="fa-solid fa-bolt-lightning"></i> RUN ASSESSMENT';
    log('err', `Connection error: ${e.message}`);
  });
});
