/* ==========================================================================
   OnionOS v1.0.0 — Onion Mesh Desktop Shell & 11 Sovereign Applications
   100% Self-Hosted | Zero innerHTML | Zero Emojis | Zero External URLs
   ========================================================================== */

(() => {
  'use strict';

  const APP_CATALOG = [
    { id: 'oniontalk', title: 'OnionTalk', desc: 'Sovereign P2P Tor Messenger & OnionVoice', w: 920, h: 600, x: 36, y: 20, pinned: true },
    { id: 'browser', title: 'Tor Browser', desc: 'On-Demand Airgapped Firefox ESR', w: 960, h: 620, x: 76, y: 24, pinned: true },
    { id: 'files', title: 'Files', desc: 'Amnesic RAM & Encrypted Vault Files', w: 880, h: 560, x: 92, y: 32, pinned: true },
    { id: 'onionshare', title: 'OnionShare', desc: 'Ephemeral .onion v3 Share & Dropzone', w: 820, h: 560, x: 112, y: 36, pinned: true },
    { id: 'passwords', title: 'Passwords & 2FA', desc: 'OTPQCV2 Secrets & Live TOTP', w: 880, h: 570, x: 84, y: 28, pinned: true },
    { id: 'editor', title: 'Text Editor', desc: 'Amnesic & Vault Markdown/Code Editor', w: 800, h: 540, x: 128, y: 40, pinned: true },
    { id: 'cleaner', title: 'Metadata & PQC', desc: 'MAT2 Scrubber, .otseal & Offline QR', w: 860, h: 560, x: 104, y: 30, pinned: true },
    { id: 'network', title: 'Tor & OSINT Lab', desc: 'Live Circuit Map, NEWNYM & Recon', w: 900, h: 580, x: 70, y: 26, pinned: true },
    { id: 'terminal', title: 'Console', desc: 'Multi-Tab Amnesic PTY Shell', w: 780, h: 500, x: 140, y: 44, pinned: true },
    { id: 'settings', title: 'System & Settings', desc: 'Kernel Monitor, Processes & Wallpaper', w: 840, h: 560, x: 96, y: 34, pinned: true },
    { id: 'relay', title: 'OnionTalk Relay', desc: 'Federated S/Kademlia & GossipSub Mesh Node', w: 880, h: 600, x: 156, y: 26, pinned: true },
  ];

  const ONION_THEME_PRESETS = [
    { id: 'onion-mesh', title: 'Onion Mesh', baseColor: '#0A0E14', primaryGlow: [37, 99, 235], secondaryGlow: [16, 185, 129] },
    { id: 'cobalt-vault', title: 'Cobalt Vault', baseColor: '#091322', primaryGlow: [59, 130, 246], secondaryGlow: [29, 78, 216] },
    { id: 'pqc-shield', title: 'PQC Shield', baseColor: '#081915', primaryGlow: [16, 185, 129], secondaryGlow: [5, 150, 105] },
    { id: 'tor-night', title: 'Tor Night', baseColor: '#120D20', primaryGlow: [139, 92, 246], secondaryGlow: [99, 102, 241] },
    { id: 'brushed-slate', title: 'Brushed Slate', baseColor: '#10161F', primaryGlow: [71, 85, 105], secondaryGlow: [51, 65, 85] },
    { id: 'stealth-oled', title: 'Stealth OLED', baseColor: '#000000', primaryGlow: [0, 0, 0], secondaryGlow: [0, 0, 0] },
  ];

  const MESH_NORMALIZED_NODES = [
    [0.14, 0.12], [0.42, 0.08], [0.82, 0.15], [0.26, 0.28], [0.66, 0.26],
    [0.12, 0.48], [0.48, 0.44], [0.86, 0.46], [0.22, 0.68], [0.60, 0.65],
    [0.88, 0.74], [0.35, 0.86], [0.74, 0.90],
  ];

  const MESH_NODE_EDGES = [
    [0, 1], [1, 2], [0, 3], [1, 3], [1, 4], [2, 4],
    [3, 5], [3, 6], [4, 6], [4, 7], [5, 6], [6, 7],
    [5, 8], [6, 8], [6, 9], [7, 9], [7, 10], [8, 9],
    [8, 11], [9, 11], [9, 10], [9, 12], [10, 12], [11, 12],
  ];

  const WALLPAPERS = ONION_THEME_PRESETS.map((p) => p.id);

  function normalizeWallpaperKey(raw) {
    const k = String(raw || '').trim().toLowerCase();
    if (WALLPAPERS.includes(k)) return k;
    if (k === 'adwaita-blue' || k === 'default') return 'onion-mesh';
    if (k === 'adwaita-amber' || k === 'sapphire') return 'cobalt-vault';
    if (k === 'emerald-grid' || k === 'emerald') return 'pqc-shield';
    if (k === 'cyber_purple') return 'tor-night';
    if (k === 'onion-obsidian' || k === 'slate') return 'brushed-slate';
    if (k === 'amoled') return 'stealth-oled';
    return 'onion-mesh';
  }

  function rgbaStr(rgb, alpha) {
    return `rgba(${rgb[0]}, ${rgb[1]}, ${rgb[2]}, ${alpha.toFixed(4)})`;
  }

  function drawOnionSignatureCanvas(canvas, themeId, previewMode = false) {
    if (!canvas) return;
    const preset = ONION_THEME_PRESETS.find((p) => p.id === themeId) || ONION_THEME_PRESETS[0];
    const rect = canvas.getBoundingClientRect();
    const cssW = Math.max(1, Math.round(rect.width || canvas.width || 320));
    const cssH = Math.max(1, Math.round(rect.height || canvas.height || 180));
    const dpr = previewMode ? 1 : Math.min(window.devicePixelRatio || 1, 2);
    const targetW = Math.round(cssW * dpr);
    const targetH = Math.round(cssH * dpr);
    if (canvas.width !== targetW || canvas.height !== targetH) {
      canvas.width = targetW;
      canvas.height = targetH;
    }
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.fillStyle = preset.baseColor;
    ctx.fillRect(0, 0, cssW, cssH);

    if (preset.id === 'stealth-oled') {
      ctx.restore();
      return;
    }

    const alphaScale = previewMode ? 1.35 : 1.0;
    const maxDim = Math.max(cssW, cssH);

    const g1 = ctx.createRadialGradient(cssW * 0.86, cssH * 0.12, 0, cssW * 0.86, cssH * 0.12, maxDim * 0.62);
    g1.addColorStop(0, rgbaStr(preset.primaryGlow, 0.085 * alphaScale));
    g1.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g1;
    ctx.fillRect(0, 0, cssW, cssH);

    const g2 = ctx.createRadialGradient(cssW * 0.14, cssH * 0.86, 0, cssW * 0.14, cssH * 0.86, maxDim * 0.56);
    g2.addColorStop(0, rgbaStr(preset.secondaryGlow, 0.055 * alphaScale));
    g2.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g2;
    ctx.fillRect(0, 0, cssW, cssH);

    if (preset.id === 'onion-mesh') {
      const ox = cssW * 0.85;
      const oy = cssH * 0.14;
      ctx.strokeStyle = rgbaStr(preset.primaryGlow, 0.052 * alphaScale);
      ctx.lineWidth = 1;
      [0.16, 0.28, 0.42, 0.58].forEach((rf) => {
        ctx.beginPath();
        ctx.arc(ox, oy, maxDim * rf, 0, Math.PI * 2);
        ctx.stroke();
      });

      ctx.strokeStyle = rgbaStr([96, 165, 250], 0.048 * alphaScale);
      ctx.lineWidth = 1;
      MESH_NODE_EDGES.forEach(([i, j]) => {
        const a = MESH_NORMALIZED_NODES[i];
        const b = MESH_NORMALIZED_NODES[j];
        ctx.beginPath();
        ctx.moveTo(a[0] * cssW, a[1] * cssH);
        ctx.lineTo(b[0] * cssW, b[1] * cssH);
        ctx.stroke();
      });

      MESH_NORMALIZED_NODES.forEach((pt, idx) => {
        const cx = pt[0] * cssW;
        const cy = pt[1] * cssH;
        const tint = (idx % 3 === 0) ? preset.secondaryGlow : [96, 165, 250];
        ctx.fillStyle = rgbaStr(tint, 0.095 * alphaScale);
        ctx.beginPath();
        ctx.arc(cx, cy, previewMode ? 1.8 : 2.2, 0, Math.PI * 2);
        ctx.fill();
        if (!previewMode && idx % 4 === 0) {
          ctx.strokeStyle = rgbaStr(tint, 0.045 * alphaScale);
          ctx.lineWidth = 0.8;
          ctx.beginPath();
          ctx.arc(cx, cy, 5, 0, Math.PI * 2);
          ctx.stroke();
        }
      });
    } else if (preset.id === 'cobalt-vault') {
      const step = previewMode ? 18 : 52;
      ctx.strokeStyle = rgbaStr(preset.primaryGlow, 0.045 * alphaScale);
      ctx.lineWidth = 0.8;
      for (let x = step; x < cssW; x += step) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, cssH); ctx.stroke();
      }
      for (let y = step; y < cssH; y += step) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(cssW, y); ctx.stroke();
      }
    } else if (preset.id === 'pqc-shield') {
      const step = previewMode ? 22 : 68;
      ctx.strokeStyle = rgbaStr(preset.primaryGlow, 0.048 * alphaScale);
      ctx.lineWidth = 0.9;
      for (let offset = -cssH; offset < cssW + cssH; offset += step) {
        ctx.beginPath();
        ctx.moveTo(offset, 0);
        ctx.lineTo(offset + cssH * 0.55, cssH);
        ctx.stroke();
      }
    } else if (preset.id === 'tor-night') {
      const cx = cssW * 0.5;
      const cy = cssH * 0.44;
      ctx.strokeStyle = rgbaStr(preset.primaryGlow, 0.058 * alphaScale);
      ctx.lineWidth = 1;
      [0.14, 0.24, 0.36, 0.50, 0.66].forEach((f) => {
        ctx.beginPath();
        ctx.arc(cx, cy, maxDim * f, 0, Math.PI * 2);
        ctx.stroke();
      });
    }
    ctx.restore();
  }

  function paintAllWallpaperCanvases() {
    const wp = normalizeWallpaperKey(state.settings.wallpaper);
    const preset = ONION_THEME_PRESETS.find((p) => p.id === wp) || ONION_THEME_PRESETS[0];
    document.documentElement.style.setProperty('--bg-root', preset.baseColor);
    drawOnionSignatureCanvas($('gdm-bg-canvas'), wp, false);
    drawOnionSignatureCanvas($('desktop-bg-canvas'), wp, false);
    document.querySelectorAll('.wallpaper-swatch').forEach((sw) => {
      const cv = sw.querySelector('canvas');
      if (cv && sw.dataset.wp) {
        drawOnionSignatureCanvas(cv, sw.dataset.wp, true);
      }
    });
  }

  const state = {
    locked: true,
    initialized: false,
    csrfToken: '',
    identityFingerprint: '',
    mlkemPubkeyHex: '',
    x25519PubkeyHex: '',
    ed25519PubkeyHex: '',
    telemetry: {},
    settings: { wallpaper: 'onion-mesh', autoLockMinutes: 15, dockCompact: false },
    lastActivityMs: Date.now(),
    notifications: [],
    vaultItems: [],
    totpMap: new Map(),
    cachedRamFiles: [],
    wm: null,
    timers: { clock: null, telemetry: null, totp: null, idle: null },
    appHooks: {},
  };

  const $ = (id) => document.getElementById(id);

  /* ------------------------------------------------------------------------
     Safe DOM Builder (Zero innerHTML) & Formatters
     ------------------------------------------------------------------------ */
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'className') node.className = v;
      else if (k === 'text') node.textContent = String(v);
      else if (k === 'hidden') node.hidden = Boolean(v);
      else if (k === 'disabled') node.disabled = Boolean(v);
      else if (k === 'checked') node.checked = Boolean(v);
      else if (k === 'value') node.value = String(v);
      else if (k === 'style' && typeof v === 'object') Object.assign(node.style, v);
      else if (k.startsWith('on') && typeof v === 'function') {
        node.addEventListener(k.slice(2).toLowerCase(), v);
      } else {
        node.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const child of children.flat()) {
      if (child === undefined || child === null || child === false) continue;
      node.appendChild(typeof child === 'string' || typeof child === 'number' ? document.createTextNode(String(child)) : child);
    }
    return node;
  }

  function formatBytes(bytes) {
    const b = Number(bytes) || 0;
    if (b < 1024) return `${b} B`;
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KiB`;
    return `${(b / (1024 * 1024)).toFixed(2)} MiB`;
  }

  function formatKib(kib) {
    const k = Number(kib) || 0;
    if (k < 1024) return `${k} KiB`;
    return `${(k / 1024).toFixed(1)} MiB`;
  }

  function formatUptime(secs) {
    const t = Math.max(0, Math.floor(Number(secs) || 0));
    const h = Math.floor(t / 3600);
    const m = Math.floor((t % 3600) / 60);
    const s = t % 60;
    if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`;
    if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`;
    return `${s}s`;
  }

  function shortHex(hex, edge = 8) {
    const s = String(hex || '');
    if (!s) return '--';
    return s.length <= edge * 2 + 3 ? s : `${s.slice(0, edge)}...${s.slice(-edge)}`;
  }

  function stripAnsi(raw) {
    // eslint-disable-next-line no-control-regex
    return String(raw || '').replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '');
  }

  function pushToast(message, isError = false) {
    const region = $('toast-region');
    const toast = el('div', { className: isError ? 'adw-toast is-error' : 'adw-toast', text: message });
    region.appendChild(toast);
    window.setTimeout(() => toast.remove(), 3800);

    state.notifications.unshift({
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }),
      message,
      isError,
    });
    state.notifications = state.notifications.slice(0, 25);
    renderNotifications();
  }

  async function copyClipboard(value, label = 'Value') {
    if (!value) {
      pushToast(`No ${label} available to copy.`, true);
      return;
    }
    try {
      await navigator.clipboard.writeText(String(value));
      pushToast(`${label} copied to clipboard.`);
    } catch {
      pushToast('Clipboard access blocked by browser.', true);
    }
  }

  function readFileBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const s = String(reader.result || '');
        const idx = s.indexOf(';base64,');
        resolve(idx >= 0 ? s.slice(idx + 8) : s);
      };
      reader.onerror = () => reject(new Error('Failed to read local file'));
      reader.readAsDataURL(file);
    });
  }

  /* ------------------------------------------------------------------------
     Authenticated API Client (Cookie + X-OnionOS-Token)
     ------------------------------------------------------------------------ */
  async function apiFetch(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (state.csrfToken) {
      headers.set('X-OnionOS-Token', state.csrfToken);
    }

    let body = options.body;
    if (body !== undefined && body !== null && typeof body === 'object' && !(body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
      body = JSON.stringify(body);
    }

    const res = await window.fetch(path, {
      method: options.method || 'GET',
      credentials: 'same-origin',
      headers,
      body,
    });

    let payload = null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      try {
        payload = await res.json();
      } catch {
        payload = null;
      }
    } else {
      const txt = await res.text();
      payload = txt ? { message: txt } : null;
    }

    if (res.status === 401 && !state.locked && !path.startsWith('/api/auth/')) {
      lockDesktopUI('Session locked or expired. Enter master passphrase to unseal.');
      throw new Error('Unauthorized');
    }

    if (!res.ok) {
      throw new Error((payload && (payload.error || payload.message || payload.reason)) || `HTTP ${res.status}`);
    }
    return payload || {};
  }

  /* ------------------------------------------------------------------------
     Clock, Calendar, Notifications & Wallpaper
     ------------------------------------------------------------------------ */
  function updateClocks() {
    const now = new Date();
    const hm = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
    const fullDate = now.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' });
    const shortBar = `${now.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' })}  ${hm}`;

    $('gdm-clock').textContent = hm;
    $('gdm-date').textContent = fullDate;
    $('top-clock-text').textContent = shortBar;
  }

  function renderCalendar() {
    const now = new Date();
    $('cal-month-title').textContent = now.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    $('cal-today-pill').textContent = now.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

    const grid = $('cal-grid');
    grid.replaceChildren();
    for (const d of ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa']) {
      grid.appendChild(el('div', { className: 'cal-cell is-head', text: d }));
    }

    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1).getDay();
    const totalDays = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();

    for (let i = 0; i < firstDay; i += 1) {
      grid.appendChild(el('div', { className: 'cal-cell', text: '' }));
    }
    for (let day = 1; day <= totalDays; day += 1) {
      const cls = day === now.getDate() ? 'cal-cell is-today' : 'cal-cell';
      grid.appendChild(el('div', { className: cls, text: day }));
    }
  }

  function renderNotifications() {
    const list = $('notif-center-list');
    if (!list) return;
    list.replaceChildren();
    if (state.notifications.length === 0) {
      list.appendChild(
        el('div', { className: 'adw-card', style: { padding: '10px' } },
          el('span', { style: { color: 'var(--text-muted)', fontSize: '12.5px' }, text: 'No active notifications. Sovereign runtime nominal.' })
        )
      );
      return;
    }
    for (const n of state.notifications) {
      list.appendChild(
        el('div', { className: 'adw-card', style: { padding: '8px 10px', gap: '3px' } },
          el('span', { className: 'mono', style: { fontSize: '11px', color: 'var(--text-subtle)' }, text: n.time }),
          el('span', { style: { fontSize: '12.5px', color: n.isError ? 'var(--adw-danger-text)' : 'var(--text-primary)' }, text: n.message })
        )
      );
    }
  }

  function applySettingsToShell(settings) {
    const wp = normalizeWallpaperKey(settings.wallpaper);
    state.settings = {
      wallpaper: wp,
      autoLockMinutes: Number(settings.autoLockMinutes ?? 15),
      dockCompact: Boolean(settings.dockCompact),
    };
    document.documentElement.setAttribute('data-wallpaper', wp);
    $('gnome-dock').classList.toggle('is-compact', state.settings.dockCompact);
    paintAllWallpaperCanvases();

    document.querySelectorAll('.wallpaper-swatch').forEach((sw) => {
      sw.classList.toggle('is-selected', sw.dataset.wp === wp);
    });

    if (state.appHooks.syncSettingsForm) {
      state.appHooks.syncSettingsForm();
    }
  }

  async function saveSystemSettings(patch) {
    const next = { ...state.settings, ...patch };
    applySettingsToShell(next);
    if (state.locked) return;
    try {
      const saved = await apiFetch('/api/system/settings', { method: 'POST', body: next });
      applySettingsToShell(saved);
    } catch (err) {
      pushToast(`Settings sync failed: ${err.message}`, true);
    }
  }

  /* ------------------------------------------------------------------------
     GDM Lock / Unlock & Session Lifecycle
     ------------------------------------------------------------------------ */
  async function refreshGdmStatus() {
    try {
      const [health, auth] = await Promise.all([
        apiFetch('/api/health').catch(() => ({})),
        apiFetch('/api/auth/status').catch(() => ({})),
      ]);
      state.initialized = Boolean(auth.initialized);
      const torOk = Boolean(health.torSocksReachable);
      $('gdm-tor-status').textContent = torOk ? 'Tor SOCKS5h: Connected' : 'Tor SOCKS5h: Bootstrapping';
      $('gdm-uptime').textContent = `OnionOS ${health.version || '1.0.0'}  |  Up ${formatUptime(health.uptimeSecs)}`;

      const badge = $('gdm-vault-badge');
      if (state.initialized) {
        badge.textContent = 'Sealed OTPQCV2 Vault';
        badge.className = 'adw-pill-badge ok';
        $('btn-gdm-submit-label').textContent = 'Unlock Session';
        $('gdm-passphrase').placeholder = 'Enter master passphrase...';
      } else {
        badge.textContent = 'First-Boot Setup (OTPQCV2)';
        badge.className = 'adw-pill-badge info';
        $('btn-gdm-submit-label').textContent = 'Initialize & Unlock';
        $('gdm-passphrase').placeholder = 'Create passphrase (min 12 chars)...';
      }

      $('gdm-fp-label').textContent = auth.identityFingerprint
        ? `ID ${shortHex(auth.identityFingerprint, 8)}`
        : 'Zero-Root Sovereign Runtime';
    } catch {
      $('gdm-tor-status').textContent = 'Core Compositor Standby';
    }
  }

  function enterDesktopSession() {
    state.locked = false;
    state.lastActivityMs = Date.now();
    $('gdm-screen').hidden = true;
    $('desktop-shell').hidden = false;
    $('gdm-error').hidden = true;
    $('qs-fp-badge').textContent = `ID: ${shortHex(state.identityFingerprint, 6)}`;

    renderCalendar();
    renderNotifications();

    pollSystemTelemetry();
    if (state.timers.telemetry) window.clearInterval(state.timers.telemetry);
    state.timers.telemetry = window.setInterval(pollSystemTelemetry, 5000);

    apiFetch('/api/system/settings')
      .then((s) => applySettingsToShell(s))
      .catch(() => {});

    apiFetch('/api/files/list?root=ram&path=/')
      .then((r) => { state.cachedRamFiles = Array.isArray(r.entries) ? r.entries : []; })
      .catch(() => {});

    apiFetch('/api/vault/items')
      .then((r) => { state.vaultItems = Array.isArray(r.items) ? r.items : []; })
      .catch(() => {});

    if (state.wm.getOpenWindows().length === 0) {
      state.wm.open('oniontalk');
    }
    window.requestAnimationFrame(paintAllWallpaperCanvases);
  }

  function lockDesktopUI(message = '') {
    state.locked = true;
    state.csrfToken = '';
    state.vaultItems = [];
    state.totpMap.clear();
    state.cachedRamFiles = [];

    if (state.timers.telemetry) {
      window.clearInterval(state.timers.telemetry);
      state.timers.telemetry = null;
    }

    closeShellPopovers();
    if (state.wm) {
      state.wm.closeAll();
    }

    $('panic-modal').hidden = true;
    $('desktop-shell').hidden = true;
    $('gdm-screen').hidden = false;

    const err = $('gdm-error');
    if (message) {
      err.textContent = message;
      err.hidden = false;
    } else {
      err.hidden = true;
    }

    refreshGdmStatus();
    $('gdm-passphrase').focus();
  }

  async function requestSessionLock() {
    try {
      await apiFetch('/api/auth/lock', { method: 'POST', body: {} });
    } catch {
      // Proceed with immediate local zeroization
    }
    lockDesktopUI('');
  }

  async function pollSystemTelemetry() {
    if (state.locked) return;
    try {
      const t = await apiFetch('/api/system/telemetry');
      state.telemetry = t;

      const bState = t.browserState || 'stopped';
      $('top-qs-summary').textContent = `${t.torSocksOk ? 'Tor OK' : 'Tor Wait'} | ${formatBytes(t.tmpfsBytes)}`;
      $('qs-sub-tor').textContent = t.torSocksOk ? 'SOCKS5h Active' : 'Bootstrapping';
      $('qs-tile-tor').classList.toggle('is-active', Boolean(t.torSocksOk));

      $('qs-sub-browser').textContent = bState === 'running' ? 'Running (:6901)' : bState === 'starting' ? 'Starting...' : 'Stopped (Lazy)';
      $('qs-tile-browser').classList.toggle('is-active', bState === 'running');

      $('qs-sub-onionshare').textContent = t.onionShareActive ? 'Hidden Service Live' : 'Inactive';
      $('qs-tile-onionshare').classList.toggle('is-active', Boolean(t.onionShareActive));

      const rState = t.relayState || 'stopped';
      $('qs-tile-relay').classList.toggle('is-emerald', rState === 'running');
      if (rState === 'running') {
        const rs = await apiFetch('/api/relay/status').catch(() => null);
        const peers = rs ? (rs.peersCount ?? 0) : 0;
        $('qs-sub-relay').textContent = `Running | ${peers} Peers`;
      } else if (rState === 'starting') {
        $('qs-sub-relay').textContent = 'Starting...';
      } else {
        $('qs-sub-relay').textContent = 'Stopped';
      }
    } catch {
      // Handled by apiFetch 401 handler
    }
  }

  /* ------------------------------------------------------------------------
     Shell Popovers, Dock & Activities Overview (Global Omnisearch)
     ------------------------------------------------------------------------ */
  function closeShellPopovers() {
    $('calendar-popover').hidden = true;
    $('qs-popover').hidden = true;
    $('activities-overview').hidden = true;
    $('desktop-ctx-menu').hidden = true;
    $('btn-activities').classList.remove('is-active');
    $('btn-activities').setAttribute('aria-expanded', 'false');
    $('btn-top-clock').classList.remove('is-active');
    $('btn-top-clock').setAttribute('aria-expanded', 'false');
    $('btn-quick-settings').classList.remove('is-active');
    $('btn-quick-settings').setAttribute('aria-expanded', 'false');
  }

  function toggleActivities(forceOpen) {
    const ov = $('activities-overview');
    const willOpen = typeof forceOpen === 'boolean' ? forceOpen : ov.hidden;
    closeShellPopovers();
    if (willOpen) {
      ov.hidden = false;
      $('btn-activities').classList.add('is-active');
      $('btn-activities').setAttribute('aria-expanded', 'true');
      renderActivitiesOverview();
      $('overview-search-input').value = '';
      $('overview-search-input').focus();
    }
  }

  function renderDockAndTopbar({ focusedId, openWindows }) {
    const runningSet = new Set(openWindows.map((w) => w.id));
    document.querySelectorAll('.dock-item[data-app-id]').forEach((btn) => {
      const id = btn.dataset.appId;
      btn.classList.toggle('is-running', runningSet.has(id));
      btn.classList.toggle('is-focused', id === focusedId);
    });

    const topAppBtn = $('btn-focused-app');
    const appMeta = APP_CATALOG.find((a) => a.id === focusedId);
    if (appMeta) {
      $('top-focused-icon').replaceChildren(window.OnionIcons.createAppIcon(appMeta.id, 18));
      $('top-focused-title').textContent = appMeta.title;
      topAppBtn.hidden = false;
    } else {
      topAppBtn.hidden = true;
    }

    if (!$('activities-overview').hidden) {
      renderActivitiesOverview();
    }
  }

  function renderActivitiesOverview() {
    const winStrip = $('overview-windows');
    winStrip.replaceChildren();
    const openWins = state.wm ? state.wm.getOpenWindows() : [];
    for (const w of openWins) {
      winStrip.appendChild(
        el('button', {
          type: 'button',
          className: 'overview-win-card',
          onClick: () => {
            closeShellPopovers();
            state.wm.open(w.id);
          },
        },
          window.OnionIcons.createAppIcon(w.id, 28),
          el('div', { style: { textAlign: 'left' } },
            el('div', { style: { fontWeight: '700', fontSize: '13px' }, text: w.title }),
            el('div', { style: { fontSize: '11px', color: 'var(--text-muted)' }, text: w.minimized ? 'Minimized' : 'Active Window' })
          )
        )
      );
    }

    const q = $('overview-search-input').value.trim().toLowerCase();
    const appGrid = $('overview-app-grid');
    const resultsBox = $('overview-results');

    if (!q) {
      resultsBox.hidden = true;
      appGrid.hidden = false;
      return;
    }

    appGrid.hidden = true;
    resultsBox.hidden = false;
    resultsBox.replaceChildren();

    const matches = [];
    for (const app of APP_CATALOG) {
      if (app.title.toLowerCase().includes(q) || app.desc.toLowerCase().includes(q)) {
        matches.push({
          icon: window.OnionIcons.createAppIcon(app.id, 28),
          title: app.title,
          sub: `Application — ${app.desc}`,
          act: () => { closeShellPopovers(); state.wm.open(app.id); },
        });
      }
    }
    for (const f of state.cachedRamFiles) {
      if (String(f.name || '').toLowerCase().includes(q)) {
        matches.push({
          icon: window.OnionIcons.createSymbolic(f.kind === 'dir' ? 'folder' : 'file', 18),
          title: f.name,
          sub: `RAM File — ${f.path}`,
          act: () => {
            closeShellPopovers();
            if (f.kind === 'file') state.wm.open('editor', { root: 'ram', path: f.path });
            else state.wm.open('files', { root: 'ram', path: f.path });
          },
        });
      }
    }
    for (const v of state.vaultItems) {
      if (String(v.title || '').toLowerCase().includes(q) || String(v.username || '').toLowerCase().includes(q)) {
        matches.push({
          icon: window.OnionIcons.createAppIcon('passwords', 26),
          title: v.title,
          sub: `Vault (${v.category || 'secret'}) ${v.username ? '— ' + v.username : ''}`,
          act: () => { closeShellPopovers(); state.wm.open('passwords'); },
        });
      }
    }

    if (matches.length === 0) {
      resultsBox.appendChild(el('div', { className: 'adw-card', text: `No matching applications, files, or vault records for "${q}".` }));
      return;
    }

    const boxed = el('div', { className: 'adw-boxed-list' });
    for (const m of matches.slice(0, 12)) {
      boxed.appendChild(
        el('button', {
          type: 'button',
          className: 'file-entry-row',
          onClick: m.act,
        },
          el('div', { className: 'adw-row-group' },
            m.icon,
            el('div', {},
              el('span', { className: 'adw-row-title', text: m.title }),
              el('span', { className: 'adw-row-sub', text: m.sub })
            )
          ),
          window.OnionIcons.createSymbolic('chevron-right', 14)
        )
      );
    }
    resultsBox.appendChild(boxed);
  }

  /* ========================================================================
     10 SOVEREIGN GNOME 47 / LIBADWAITA APPLICATIONS
     ======================================================================== */

  /* 1. OnionTalk (/ot/) */
  function registerOnionTalkApp(wm) {
    let iframe = null;
    wm.registerApp({
      ...APP_CATALOG[0],
      defaultWidth: 920,
      defaultHeight: 600,
      defaultLeft: 48,
      defaultTop: 18,
      buildContent(ctx) {
        ctx.startSlot.append(
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            onClick: () => { if (iframe) iframe.src = '/ot/'; },
          }, window.OnionIcons.createSymbolic('refresh', 14), 'Reload'),
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            onClick: () => copyClipboard(state.identityFingerprint, 'Identity Fingerprint'),
          }, window.OnionIcons.createSymbolic('copy', 14), 'Copy ID')
        );
        ctx.endSlot.append(
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm adw-btn-suggested',
            title: 'Open OnionTalk Federated Relay Node',
            onClick: () => wm.open('relay'),
          }, window.OnionIcons.createSymbolic('relay-symbolic', 14), 'Relay'),
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            title: 'Open Passwords & 2FA Vault',
            onClick: () => wm.open('passwords'),
          }, window.OnionIcons.createSymbolic('key', 14), 'Vault')
        );

        iframe = el('iframe', {
          className: 'embed-iframe',
          title: 'OnionTalk Sovereign Messenger',
          allow: 'microphone; clipboard-read; clipboard-write',
        });
        ctx.root.appendChild(iframe);
      },
      onOpen() {
        if (iframe && (!iframe.getAttribute('src') || iframe.getAttribute('src') === 'about:blank')) {
          iframe.setAttribute('src', '/ot/');
        }
      },
      onClose() {
        if (iframe) iframe.setAttribute('src', 'about:blank');
      },
    });
  }

  /* 2. Tor Browser (Lazy On-Demand Firefox ESR + noVNC) */
  function registerBrowserApp(wm) {
    let statusPage = null;
    let statusTitle = null;
    let statusDesc = null;
    let launchBtn = null;
    let vncFrame = null;
    let stopBtn = null;
    let wipeBtn = null;
    let pollTimer = null;

    function ensureBrowserPoll() {
      if (!pollTimer) {
        pollTimer = window.setInterval(syncBrowserStatus, 2500);
      }
    }

    async function syncBrowserStatus() {
      if (state.locked) return;
      try {
        const s = await apiFetch('/api/browser/status');
        const runningReady = s.state === 'running' && s.wsReady !== false;
        stopBtn.disabled = s.state === 'stopped';
        wipeBtn.disabled = s.state === 'stopped';

        if (runningReady) {
          statusPage.hidden = true;
          vncFrame.hidden = false;
          const url = s.launchUrl || '/sandbox/vnc.html?autoconnect=true&resize=scale';
          if (vncFrame.getAttribute('src') !== url) {
            vncFrame.setAttribute('src', url);
          }
        } else if (s.state === 'stopped') {
          vncFrame.hidden = true;
          if (vncFrame.getAttribute('src') && vncFrame.getAttribute('src') !== 'about:blank') {
            vncFrame.setAttribute('src', 'about:blank');
          }
          statusPage.hidden = false;
          statusTitle.textContent = 'Tor Browser Engine Suspended';
          statusDesc.textContent = 'On-demand spawning saves ~420 MiB of RAM while idle. Profile lives exclusively in volatile tmpfs and routes 100% through Tor.';
          launchBtn.disabled = false;
        } else {
          // s.state === 'starting' or transient probe check: only show spinner if vncFrame is not already active
          if (vncFrame.hidden || !vncFrame.getAttribute('src') || vncFrame.getAttribute('src') === 'about:blank') {
            vncFrame.hidden = true;
            statusPage.hidden = false;
            statusTitle.textContent = 'Starting Airgapped Tor Browser...';
            statusDesc.textContent = 'Spawning Xvfb, x11vnc, websockify, and Firefox ESR over UID-locked Tor SOCKS5h.';
            launchBtn.disabled = true;
          }
        }
      } catch (err) {
        pushToast(`Browser status error: ${err.message}`, true);
      }
    }

    async function startBrowserEngine() {
      launchBtn.disabled = true;
      statusTitle.textContent = 'Launching Tor Browser...';
      try {
        await apiFetch('/api/browser/start', { method: 'POST', body: {} });
        await syncBrowserStatus();
        pollSystemTelemetry();
        ensureBrowserPoll();
      } catch (err) {
        launchBtn.disabled = false;
        pushToast(`Failed to start Tor Browser: ${err.message}`, true);
      }
    }

    state.appHooks.toggleBrowserFromQs = () => {
      wm.open('browser');
      if (state.telemetry.browserState === 'stopped') {
        startBrowserEngine();
      }
    };

    wm.registerApp({
      ...APP_CATALOG[1],
      defaultWidth: 960,
      defaultHeight: 620,
      defaultLeft: 72,
      defaultTop: 22,
      buildContent(ctx) {
        wipeBtn = el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-sm',
          disabled: true,
          onClick: async () => {
            try {
              await apiFetch('/api/sandbox/reset', { method: 'POST', body: {} });
              pushToast('Ephemeral Firefox profile wiped.');
              if (!vncFrame.hidden) {
                const cur = vncFrame.getAttribute('src');
                vncFrame.setAttribute('src', 'about:blank');
                window.setTimeout(() => vncFrame.setAttribute('src', cur), 250);
              }
            } catch (err) {
              pushToast(`Wipe failed: ${err.message}`, true);
            }
          },
        }, window.OnionIcons.createSymbolic('trash', 14), 'Wipe Profile');

        stopBtn = el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-sm adw-btn-destructive',
          disabled: true,
          onClick: async () => {
            try {
              await apiFetch('/api/browser/stop', { method: 'POST', body: {} });
              pushToast('Tor Browser engine stopped and RAM reclaimed.');
              await syncBrowserStatus();
              pollSystemTelemetry();
            } catch (err) {
              pushToast(`Stop failed: ${err.message}`, true);
            }
          },
        }, window.OnionIcons.createSymbolic('power', 14), 'Stop Engine');

        ctx.startSlot.append(wipeBtn);
        ctx.endSlot.append(stopBtn);

        statusTitle = el('h3', { className: 'adw-status-title', text: 'Tor Browser Engine Suspended' });
        statusDesc = el('p', {
          className: 'adw-status-desc',
          text: 'On-demand spawning saves ~420 MiB of RAM while idle. Profile lives exclusively in volatile tmpfs and routes 100% through Tor.',
        });
        launchBtn = el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-suggested adw-btn-pill',
          onClick: startBrowserEngine,
        }, 'Launch Tor Browser');

        statusPage = el('div', { className: 'adw-status-page' },
          window.OnionIcons.createAppIcon('browser', 76),
          statusTitle,
          statusDesc,
          launchBtn
        );

        vncFrame = el('iframe', { className: 'embed-iframe', title: 'Tor Browser Isolated Session', hidden: true });
        ctx.root.append(statusPage, vncFrame);
      },
      onOpen() {
        syncBrowserStatus();
        ensureBrowserPoll();
      },
      onClose() {
        if (pollTimer) {
          window.clearInterval(pollTimer);
          pollTimer = null;
        }
        if (vncFrame) vncFrame.setAttribute('src', 'about:blank');
      },
    });
  }

  /* 3. Files (GNOME Nautilus Dual-Root: RAM + Encrypted Vault) */
  function registerFilesApp(wm) {
    let curRoot = 'ram';
    let curPath = '/';
    let entries = [];
    let selectedEntry = null;
    let listBox = null;
    let inspectorBox = null;
    let pathBadge = null;
    let promptBar = null;
    let promptInput = null;
    let promptMode = '';
    const navButtons = [];

    function joinPath(base, name) {
      const cleanName = String(name || '').replace(/^\/+/, '');
      if (!base || base === '/') return `/${cleanName}`;
      return `${base.replace(/\/+$/, '')}/${cleanName}`;
    }

    function parentPath(p) {
      if (!p || p === '/') return '/';
      const idx = p.lastIndexOf('/');
      return idx <= 0 ? '/' : p.slice(0, idx);
    }

    async function loadDirectory(root = curRoot, path = curPath) {
      curRoot = root;
      curPath = path || '/';
      selectedEntry = null;
      navButtons.forEach((b) => {
        b.el.classList.toggle('is-active', b.root === curRoot && b.path === curPath);
      });
      pathBadge.textContent = `${curRoot === 'vault' ? 'vault:' : 'ram:'}${curPath}`;

      try {
        const res = await apiFetch(`/api/files/list?root=${encodeURIComponent(curRoot)}&path=${encodeURIComponent(curPath)}`);
        entries = Array.isArray(res.entries) ? res.entries : [];
        if (curRoot === 'ram' && curPath === '/') {
          state.cachedRamFiles = entries;
        }
        renderEntries();
        renderInspector(null);
      } catch (err) {
        if (curPath !== '/') {
          await apiFetch('/api/files/mkdir', { method: 'POST', body: { root: curRoot, path: curPath } }).catch(() => {});
          const retry = await apiFetch(`/api/files/list?root=${encodeURIComponent(curRoot)}&path=${encodeURIComponent(curPath)}`).catch(() => ({ entries: [] }));
          entries = Array.isArray(retry.entries) ? retry.entries : [];
          renderEntries();
          renderInspector(null);
        } else {
          pushToast(`Files error: ${err.message}`, true);
        }
      }
    }

    function renderEntries() {
      listBox.replaceChildren();
      if (curPath !== '/') {
        listBox.appendChild(
          el('button', {
            type: 'button',
            className: 'file-entry-row',
            onClick: () => loadDirectory(curRoot, parentPath(curPath)),
          },
            el('div', { className: 'adw-row-group' },
              window.OnionIcons.createSymbolic('chevron-left', 15),
              el('span', { className: 'adw-row-title', text: '.. (Parent Directory)' })
            )
          )
        );
      }

      if (entries.length === 0) {
        listBox.appendChild(
          el('div', { className: 'adw-status-page' },
            window.OnionIcons.createSymbolic('folder', 36),
            el('div', { style: { fontWeight: '700' }, text: 'Folder is Empty' }),
            el('div', { style: { fontSize: '12.5px', color: 'var(--text-muted)' },
              text: curRoot === 'vault' ? 'Files saved here are sealed atomically in OTPQCV2.' : 'Volatile tmpfs directory in /home/onion.'
            })
          )
        );
        return;
      }

      for (const item of entries) {
        const isSel = selectedEntry && selectedEntry.path === item.path;
        listBox.appendChild(
          el('button', {
            type: 'button',
            className: isSel ? 'file-entry-row is-selected' : 'file-entry-row',
            onClick: () => {
              if (item.kind === 'dir') {
                loadDirectory(curRoot, item.path);
              } else {
                selectedEntry = item;
                renderEntries();
                inspectFile(item);
              }
            },
          },
            el('div', { className: 'adw-row-group' },
              window.OnionIcons.createSymbolic(item.kind === 'dir' ? 'folder' : 'file', 17),
              el('div', {},
                el('span', { className: 'adw-row-title', text: item.name }),
                el('span', { className: 'adw-row-sub mono', text: item.kind === 'dir' ? 'Directory' : `${formatBytes(item.sizeBytes)}  |  ${item.mime || 'application/octet-stream'}` })
              )
            ),
            el('span', { className: 'mono', style: { fontSize: '11.5px', color: 'var(--text-subtle)' }, text: item.modifiedAt ? String(item.modifiedAt).slice(0, 19).replace('T', ' ') : '' })
          )
        );
      }
    }

    async function inspectFile(item) {
      renderInspector(item, null, true);
      try {
        const detail = await apiFetch(`/api/files/read?root=${encodeURIComponent(curRoot)}&path=${encodeURIComponent(item.path)}`);
        renderInspector(item, detail, false);
      } catch (err) {
        pushToast(`Read failed: ${err.message}`, true);
      }
    }

    function renderInspector(item, detail = null, loading = false) {
      inspectorBox.replaceChildren();
      if (!item) {
        inspectorBox.append(
          el('strong', { text: 'File Inspector' }),
          el('span', { style: { fontSize: '12.5px', color: 'var(--text-muted)' }, text: 'Select any file to preview contents, scrub forensic metadata, seal as .otseal, or shred.' })
        );
        return;
      }

      inspectorBox.append(
        el('strong', { style: { wordBreak: 'break-all' }, text: item.name }),
        el('span', { className: 'adw-pill-badge info mono', text: `${curRoot}:${item.path}` }),
        el('span', { className: 'mono', style: { fontSize: '12px', color: 'var(--text-muted)' }, text: `Size: ${formatBytes(item.sizeBytes)}` })
      );

      if (loading) {
        inspectorBox.appendChild(el('span', { style: { fontSize: '12px', color: 'var(--text-muted)' }, text: 'Reading in-memory buffer...' }));
        return;
      }

      if (detail && detail.isUtf8 && typeof detail.text === 'string') {
        inspectorBox.appendChild(
          el('pre', {
            className: 'adw-card mono',
            style: { margin: '0', maxHeight: '140px', overflow: 'auto', fontSize: '11.5px', whiteSpace: 'pre-wrap' },
            text: detail.text.slice(0, 1200),
          })
        );
      }

      const actionsCol = el('div', { style: { display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '4px' } },
        el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-sm adw-btn-suggested',
          onClick: () => wm.open('editor', { root: curRoot, path: item.path }),
        }, window.OnionIcons.createSymbolic('edit', 14), 'Open in Text Editor'),

        el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-sm',
          onClick: () => {
            if (!detail) return;
            let blob;
            if (detail.dataB64) {
              const bin = window.atob(detail.dataB64);
              const arr = new Uint8Array(bin.length);
              for (let i = 0; i < bin.length; i += 1) arr[i] = bin.charCodeAt(i);
              blob = new Blob([arr], { type: detail.mime || 'application/octet-stream' });
            } else {
              blob = new Blob([detail.text || ''], { type: 'text/plain;charset=utf-8' });
            }
            const url = URL.createObjectURL(blob);
            const a = el('a', { href: url, download: item.name });
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.setTimeout(() => URL.revokeObjectURL(url), 1000);
          },
        }, window.OnionIcons.createSymbolic('download', 14), 'Download'),

        el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-sm',
          onClick: async () => {
            try {
              const r = await apiFetch('/api/files/action', { method: 'POST', body: { root: curRoot, path: item.path, action: 'scrub' } });
              pushToast(`Scrubbed -> ${r.outputPath || 'clean copy'}`);
              loadDirectory(curRoot, curPath);
            } catch (err) {
              pushToast(`MAT2 scrub error: ${err.message}`, true);
            }
          },
        }, window.OnionIcons.createSymbolic('shield', 14), 'Scrub Metadata (MAT2)'),

        el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-sm',
          onClick: async () => {
            try {
              const r = await apiFetch('/api/files/action', { method: 'POST', body: { root: curRoot, path: item.path, action: 'seal' } });
              pushToast(`Sealed PQC -> ${r.outputPath || '.otseal'}`);
              loadDirectory(curRoot, curPath);
            } catch (err) {
              pushToast(`PQC seal error: ${err.message}`, true);
            }
          },
        }, window.OnionIcons.createSymbolic('lock', 14), 'Seal .otseal'),

        el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-sm adw-btn-destructive',
          onClick: async () => {
            try {
              await apiFetch('/api/files/delete', { method: 'POST', body: { root: curRoot, path: item.path, shred: true } });
              pushToast(`Shredded & unlinked ${item.name}.`);
              loadDirectory(curRoot, curPath);
              pollSystemTelemetry();
            } catch (err) {
              pushToast(`Delete failed: ${err.message}`, true);
            }
          },
        }, window.OnionIcons.createSymbolic('trash', 14), 'Shred & Delete')
      );

      inspectorBox.appendChild(actionsCol);
    }

    wm.registerApp({
      ...APP_CATALOG[2],
      defaultWidth: 900,
      defaultHeight: 560,
      defaultLeft: 86,
      defaultTop: 28,
      buildContent(ctx) {
        const uploadInput = el('input', {
          type: 'file',
          hidden: true,
          onChange: async () => {
            const file = uploadInput.files && uploadInput.files[0];
            if (!file) return;
            try {
              const dataB64 = await readFileBase64(file);
              const dest = joinPath(curPath, file.name);
              await apiFetch('/api/files/write', { method: 'POST', body: { root: curRoot, path: dest, dataB64 } });
              pushToast(`Uploaded ${file.name} to ${curRoot}:${dest}`);
              uploadInput.value = '';
              loadDirectory(curRoot, curPath);
              pollSystemTelemetry();
            } catch (err) {
              pushToast(`Upload error: ${err.message}`, true);
            }
          },
        });

        ctx.startSlot.append(
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            onClick: () => {
              promptMode = 'mkdir';
              promptInput.placeholder = 'New folder name...';
              promptInput.value = '';
              promptBar.hidden = false;
              promptInput.focus();
            },
          }, window.OnionIcons.createSymbolic('plus', 13), 'Folder'),
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            onClick: () => {
              promptMode = 'newfile';
              promptInput.placeholder = 'New file name (e.g. note.md)...';
              promptInput.value = '';
              promptBar.hidden = false;
              promptInput.focus();
            },
          }, window.OnionIcons.createSymbolic('file', 13), 'New File'),
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            onClick: () => uploadInput.click(),
          }, window.OnionIcons.createSymbolic('upload', 13), 'Upload'),
          uploadInput
        );

        ctx.endSlot.append(
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            onClick: () => loadDirectory(curRoot, curPath),
          }, window.OnionIcons.createSymbolic('refresh', 13))
        );

        const sidebar = el('aside', { className: 'adw-sidebar' });
        const places = [
          { label: 'Amnesic RAM', root: 'ram', path: '/', ico: 'folder' },
          { label: 'Documents', root: 'ram', path: '/Documents', ico: 'file' },
          { label: 'Downloads', root: 'ram', path: '/Downloads', ico: 'download' },
          { label: 'OnionShare', root: 'ram', path: '/OnionShare', ico: 'share' },
          { label: 'Encrypted Vault', root: 'vault', path: '/', ico: 'lock' },
        ];
        for (const p of places) {
          const row = el('button', {
            type: 'button',
            className: 'adw-nav-row',
            onClick: () => loadDirectory(p.root, p.path),
          },
            el('span', { className: 'adw-row-group' }, window.OnionIcons.createSymbolic(p.ico, 15), p.label)
          );
          navButtons.push({ ...p, el: row });
          sidebar.appendChild(row);
        }

        pathBadge = el('span', { className: 'adw-pill-badge mono', text: 'ram:/' });
        promptInput = el('input', { type: 'text', className: 'adw-entry', style: { width: '220px', height: '28px' } });
        promptBar = el('form', {
          className: 'adw-row-group',
          hidden: true,
          onSubmit: async (e) => {
            e.preventDefault();
            const name = promptInput.value.trim();
            if (!name) return;
            const target = joinPath(curPath, name);
            try {
              if (promptMode === 'mkdir') {
                await apiFetch('/api/files/mkdir', { method: 'POST', body: { root: curRoot, path: target } });
                pushToast(`Created folder ${target}`);
              } else {
                await apiFetch('/api/files/write', { method: 'POST', body: { root: curRoot, path: target, text: '' } });
                wm.open('editor', { root: curRoot, path: target });
              }
              promptBar.hidden = true;
              loadDirectory(curRoot, curPath);
            } catch (err) {
              pushToast(`Create error: ${err.message}`, true);
            }
          },
        },
          promptInput,
          el('button', { type: 'submit', className: 'adw-btn adw-btn-sm adw-btn-suggested', text: 'Create' }),
          el('button', { type: 'button', className: 'adw-btn adw-btn-sm', onClick: () => { promptBar.hidden = true; }, text: 'Cancel' })
        );

        const subToolbar = el('div', { className: 'adw-toolbar' }, pathBadge, promptBar);
        listBox = el('div', { style: { overflowY: 'auto' } });
        inspectorBox = el('div', { className: 'files-inspector' });

        const mainCol = el('div', { style: { display: 'flex', flexDirection: 'column', minHeight: '0' } },
          subToolbar,
          el('div', { className: 'files-layout' }, listBox, inspectorBox)
        );

        ctx.root.appendChild(el('div', { className: 'adw-split-view' }, sidebar, mainCol));
      },
      onOpen(payload) {
        if (payload && payload.root) {
          loadDirectory(payload.root, payload.path || '/');
        } else {
          loadDirectory(curRoot, curPath);
        }
      },
    });
  }

  /* 4. OnionShare Dropzone (ADD_ONION / DEL_ONION Hidden Service) */
  function registerOnionShareApp(wm) {
    let mode = 'share';
    let ramFiles = [];
    const selectedPaths = new Set();
    let filesChecklist = null;
    let noteInput = null;
    let codeInput = null;
    let autoStopCheck = null;
    let activeCard = null;
    let configCard = null;
    let qrSlot = null;
    let urlDisplay = null;
    let statsDisplay = null;
    let receivedBox = null;
    let statusTimer = null;

    async function refreshCandidateFiles() {
      try {
        const [rootRes, docRes] = await Promise.all([
          apiFetch('/api/files/list?root=ram&path=/').catch(() => ({ entries: [] })),
          apiFetch('/api/files/list?root=ram&path=/Documents').catch(() => ({ entries: [] })),
        ]);
        ramFiles = [...(rootRes.entries || []), ...(docRes.entries || [])].filter((e) => e.kind === 'file');
        renderChecklist();
      } catch {
        // Ignore if empty
      }
    }

    function renderChecklist() {
      filesChecklist.replaceChildren();
      if (ramFiles.length === 0) {
        filesChecklist.appendChild(el('div', { style: { fontSize: '12.5px', color: 'var(--text-muted)', padding: '8px' }, text: 'No files in /home/onion yet. Create or upload files in Files / Text Editor, or share a text note below.' }));
        return;
      }
      for (const f of ramFiles) {
        const id = `os-chk-${f.path}`;
        filesChecklist.appendChild(
          el('label', { className: 'adw-action-row', for: id, style: { cursor: 'pointer' } },
            el('span', { className: 'mono', style: { fontSize: '12.5px' }, text: `${f.path} (${formatBytes(f.sizeBytes)})` }),
            el('input', {
              id,
              type: 'checkbox',
              checked: selectedPaths.has(f.path),
              onChange: (e) => {
                if (e.target.checked) selectedPaths.add(f.path);
                else selectedPaths.delete(f.path);
              },
            })
          )
        );
      }
    }

    async function syncOnionShareStatus() {
      if (state.locked) return;
      try {
        const s = await apiFetch('/api/onionshare/status');
        if (s.active) {
          configCard.hidden = true;
          activeCard.hidden = false;
          const url = s.onionUrl || (s.onionAddress ? `http://${s.onionAddress}` : '');
          urlDisplay.textContent = url || '--';
          statsDisplay.textContent = `Mode: ${String(s.mode || 'share').toUpperCase()}  |  Downloads: ${s.downloadsCount ?? 0}  |  Auto-stop: ${s.autoStopFirstDownload ? 'Yes' : 'No'}`;

          if (url && qrSlot.dataset.qrFor !== url) {
            qrSlot.dataset.qrFor = url;
            const qrRes = await apiFetch('/api/qr/svg', { method: 'POST', body: { text: url } }).catch(() => null);
            if (qrRes && qrRes.svg) {
              qrSlot.replaceChildren(window.OnionIcons.parseSafeSvg(qrRes.svg));
            }
          }

          receivedBox.replaceChildren();
          const rec = Array.isArray(s.receivedFiles) ? s.receivedFiles : [];
          if (rec.length > 0) {
            for (const rf of rec) {
              receivedBox.appendChild(
                el('div', { className: 'adw-action-row' },
                  el('span', { className: 'mono', text: rf.name }),
                  el('span', { className: 'mono', style: { color: 'var(--text-muted)' }, text: formatBytes(rf.sizeBytes) })
                )
              );
            }
          }
        } else {
          activeCard.hidden = true;
          configCard.hidden = false;
          qrSlot.dataset.qrFor = '';
        }
      } catch {
        // Ignore transient status error
      }
    }

    wm.registerApp({
      ...APP_CATALOG[3],
      defaultWidth: 820,
      defaultHeight: 560,
      defaultLeft: 108,
      defaultTop: 32,
      buildContent(ctx) {
        const shareBtn = el('button', {
          type: 'button',
          className: 'adw-switcher-btn is-active',
          text: 'Share Files',
          onClick: () => {
            mode = 'share';
            shareBtn.classList.add('is-active');
            dropBtn.classList.remove('is-active');
            filesChecklist.parentElement.hidden = false;
          },
        });
        const dropBtn = el('button', {
          type: 'button',
          className: 'adw-switcher-btn',
          text: 'Anonymous Dead-Drop',
          onClick: () => {
            mode = 'drop';
            dropBtn.classList.add('is-active');
            shareBtn.classList.remove('is-active');
            filesChecklist.parentElement.hidden = true;
          },
        });

        ctx.centerSlot.replaceChildren(el('div', { className: 'adw-view-switcher' }, shareBtn, dropBtn));

        filesChecklist = el('div', { className: 'adw-boxed-list' });
        noteInput = el('textarea', { className: 'adw-textarea', placeholder: 'Optional note or instructions displayed on the .onion page...' });
        codeInput = el('input', { type: 'text', className: 'adw-entry mono', placeholder: 'Optional access code (leave blank for public .onion)...' });
        autoStopCheck = el('input', { type: 'checkbox', checked: true });

        configCard = el('form', {
          className: 'adw-page-pad',
          onSubmit: async (e) => {
            e.preventDefault();
            try {
              await apiFetch('/api/onionshare/start', {
                method: 'POST',
                body: {
                  mode,
                  paths: mode === 'share' ? Array.from(selectedPaths) : [],
                  note: noteInput.value.trim() || undefined,
                  accessCode: codeInput.value.trim() || undefined,
                  autoStopFirstDownload: Boolean(autoStopCheck.checked),
                },
              });
              pushToast('Ephemeral ED25519-V3 .onion service published via Tor ControlPort.');
              await syncOnionShareStatus();
              pollSystemTelemetry();
            } catch (err) {
              pushToast(`OnionShare start failed: ${err.message}`, true);
            }
          },
        },
          el('div', {},
            el('div', { style: { fontWeight: '700', marginBottom: '6px' }, text: 'Select Files from /home/onion' }),
            filesChecklist
          ),
          el('div', { className: 'grid-2' },
            el('div', { style: { display: 'flex', flexDirection: 'column', gap: '6px' } },
              el('label', { text: 'Access Code Protection', style: { fontWeight: '600', fontSize: '12.5px' } }),
              el('div', { className: 'adw-row-group' },
                codeInput,
                el('button', {
                  type: 'button',
                  className: 'adw-btn adw-btn-sm',
                  onClick: async () => {
                    const g = await apiFetch('/api/pqc/generate-secret', { method: 'POST', body: { mode: 'passphrase', length: 3 } }).catch(() => null);
                    if (g && g.secret) codeInput.value = g.secret;
                  },
                }, 'Generate')
              )
            ),
            el('label', { className: 'adw-card', style: { flexDirection: 'row', alignItems: 'center', cursor: 'pointer', marginTop: '20px' } },
              autoStopCheck,
              el('span', { text: 'Auto-destroy (.onion DEL_ONION) after 1st download' })
            )
          ),
          el('div', { style: { display: 'flex', flexDirection: 'column', gap: '6px' } },
            el('label', { text: 'Cover Note (Optional)', style: { fontWeight: '600', fontSize: '12.5px' } }),
            noteInput
          ),
          el('button', { type: 'submit', className: 'adw-btn adw-btn-success adw-btn-pill', style: { alignSelf: 'flex-start' } },
            'Start .onion Hidden Service'
          )
        );

        urlDisplay = el('code', { className: 'mono', style: { fontSize: '13px', wordBreak: 'break-all', color: 'var(--adw-success-text)' }, text: '--' });
        statsDisplay = el('div', { className: 'tabular', style: { fontSize: '12.5px', color: 'var(--text-muted)' }, text: '--' });
        qrSlot = el('div', { className: 'qr-box' });
        receivedBox = el('div', { className: 'adw-boxed-list' });

        activeCard = el('div', { className: 'adw-page-pad', hidden: true },
          el('div', { className: 'adw-card', style: { alignItems: 'center', textAlign: 'center' } },
            el('span', { className: 'adw-pill-badge ok', text: 'LIVE ED25519-V3 HIDDEN SERVICE' }),
            urlDisplay,
            statsDisplay,
            qrSlot,
            el('div', { className: 'adw-row-group' },
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-suggested',
                onClick: () => copyClipboard(urlDisplay.textContent, '.onion URL'),
              }, window.OnionIcons.createSymbolic('copy', 14), 'Copy .onion URL'),
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-destructive',
                onClick: async () => {
                  try {
                    await apiFetch('/api/onionshare/stop', { method: 'POST', body: {} });
                    pushToast('Hidden service terminated (DEL_ONION).');
                    await syncOnionShareStatus();
                    pollSystemTelemetry();
                  } catch (err) {
                    pushToast(`Stop failed: ${err.message}`, true);
                  }
                },
              }, 'Stop Hidden Service')
            )
          ),
          el('div', {},
            el('strong', { style: { display: 'block', marginBottom: '6px' }, text: 'Received Dead-Drop Artifacts' }),
            receivedBox
          )
        );

        ctx.root.append(configCard, activeCard);
      },
      onOpen() {
        refreshCandidateFiles();
        syncOnionShareStatus();
        if (!statusTimer) statusTimer = window.setInterval(syncOnionShareStatus, 3000);
      },
      onClose() {
        if (statusTimer) {
          window.clearInterval(statusTimer);
          statusTimer = null;
        }
      },
    });
  }

  /* 5. Passwords & 2FA Authenticator (OTPQCV2 + Live RFC 6238 TOTP) */
  function registerPasswordsApp(wm) {
    let curCat = 'all';
    let searchQ = '';
    const revealed = new Set();
    let listWrap = null;
    let createPanel = null;
    let totpInterval = null;
    const catBtns = [];

    async function loadVaultAndTotp() {
      if (state.locked) return;
      try {
        const [vRes, tRes] = await Promise.all([
          apiFetch('/api/vault/items'),
          apiFetch('/api/totp/codes').catch(() => ({ codes: [] })),
        ]);
        state.vaultItems = Array.isArray(vRes.items) ? vRes.items : [];
        state.totpMap.clear();
        for (const c of tRes.codes || []) {
          state.totpMap.set(c.id, c);
        }
        renderSecretsList();
      } catch (err) {
        pushToast(`Vault sync failed: ${err.message}`, true);
      }
    }

    async function refreshTotpOnly() {
      if (state.locked) return;
      try {
        const tRes = await apiFetch('/api/totp/codes');
        state.totpMap.clear();
        for (const c of tRes.codes || []) {
          state.totpMap.set(c.id, c);
        }
        renderSecretsList();
      } catch {
        // Ignore transient tick failure
      }
    }

    function renderSecretsList() {
      listWrap.replaceChildren();
      const q = searchQ.trim().toLowerCase();
      const filtered = state.vaultItems.filter((item) => {
        const cat = String(item.category || 'login').toLowerCase();
        const catMatch =
          curCat === 'all' ||
          (curCat === 'totp' ? Boolean(item.hasTotp) : cat === curCat);
        const qMatch =
          !q ||
          String(item.title || '').toLowerCase().includes(q) ||
          String(item.username || '').toLowerCase().includes(q) ||
          String(item.url || '').toLowerCase().includes(q);
        return catMatch && qMatch;
      });

      if (filtered.length === 0) {
        listWrap.appendChild(
          el('div', { className: 'adw-card', text: 'No vault records in this view. Click "+ New Item" in the HeaderBar to seal credentials, 2FA TOTP keys, or seeds.' })
        );
        return;
      }

      const boxed = el('div', { className: 'adw-boxed-list' });
      for (const item of filtered) {
        const totp = state.totpMap.get(item.id);
        const isRev = revealed.has(item.id);
        const formattedCode = totp && totp.code ? `${totp.code.slice(0, 3)} ${totp.code.slice(3)}` : '';

        boxed.appendChild(
          el('div', { className: 'adw-action-row', style: { flexWrap: 'wrap' } },
            el('div', { style: { minWidth: '200px', flex: '1' } },
              el('div', { className: 'adw-row-group' },
                el('span', { className: 'adw-row-title', text: item.title }),
                el('span', { className: 'adw-pill-badge', text: item.category || 'login' }),
                item.hasTotp ? el('span', { className: 'adw-pill-badge info', text: '2FA TOTP' }) : null
              ),
              item.username ? el('span', { className: 'adw-row-sub mono', text: `User: ${item.username}` }) : null,
              el('span', { className: 'adw-row-sub mono', text: isRev ? item.content : '********************' })
            ),

            totp
              ? el('div', { className: 'adw-row-group' },
                  el('span', { className: 'totp-code', text: formattedCode }),
                  el('span', { className: 'adw-pill-badge tabular', text: `${totp.remainingSecs}s` }),
                  el('button', {
                    type: 'button',
                    className: 'adw-btn adw-btn-sm adw-btn-suggested',
                    onClick: () => copyClipboard(totp.code, `${item.title} 2FA code`),
                  }, 'Copy 2FA')
                )
              : null,

            el('div', { className: 'adw-row-group' },
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-sm',
                onClick: () => {
                  if (revealed.has(item.id)) revealed.delete(item.id);
                  else revealed.add(item.id);
                  renderSecretsList();
                },
              }, window.OnionIcons.createSymbolic(isRev ? 'eye-off' : 'eye', 14)),
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-sm',
                onClick: () => copyClipboard(item.content, `${item.title} secret`),
              }, window.OnionIcons.createSymbolic('copy', 14), 'Copy'),
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-sm adw-btn-destructive',
                onClick: async () => {
                  try {
                    await apiFetch(`/api/vault/items/${encodeURIComponent(item.id)}`, { method: 'DELETE' });
                    pushToast(`Removed ${item.title} from OTPQCV2.`);
                    loadVaultAndTotp();
                  } catch (err) {
                    pushToast(`Delete error: ${err.message}`, true);
                  }
                },
              }, window.OnionIcons.createSymbolic('trash', 14))
            )
          )
        );
      }
      listWrap.appendChild(boxed);
    }

    wm.registerApp({
      ...APP_CATALOG[4],
      defaultWidth: 900,
      defaultHeight: 580,
      defaultLeft: 82,
      defaultTop: 26,
      buildContent(ctx) {
        ctx.startSlot.appendChild(
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm adw-btn-suggested',
            onClick: () => { createPanel.hidden = !createPanel.hidden; },
          }, window.OnionIcons.createSymbolic('plus', 13), 'New Item')
        );

        const searchInput = el('input', {
          type: 'search',
          className: 'adw-entry',
          style: { width: '190px', height: '28px' },
          placeholder: 'Filter vault...',
          onInput: (e) => {
            searchQ = e.target.value;
            renderSecretsList();
          },
        });
        ctx.endSlot.appendChild(searchInput);

        const sidebar = el('aside', { className: 'adw-sidebar' });
        const cats = [
          { id: 'all', label: 'All Items', ico: 'key' },
          { id: 'login', label: 'Logins', ico: 'lock' },
          { id: 'totp', label: '2FA Authenticator', ico: 'shield' },
          { id: 'seed', label: 'Crypto Seeds', ico: 'cpu' },
          { id: 'note', label: 'Secure Notes', ico: 'file' },
        ];
        for (const c of cats) {
          const b = el('button', {
            type: 'button',
            className: c.id === 'all' ? 'adw-nav-row is-active' : 'adw-nav-row',
            onClick: () => {
              curCat = c.id;
              catBtns.forEach((x) => x.el.classList.toggle('is-active', x.id === curCat));
              renderSecretsList();
            },
          }, el('span', { className: 'adw-row-group' }, window.OnionIcons.createSymbolic(c.ico, 15), c.label));
          catBtns.push({ id: c.id, el: b });
          sidebar.appendChild(b);
        }

        const fTitle = el('input', { type: 'text', className: 'adw-entry', placeholder: 'Title (e.g. Sovereign GitLab)', required: true });
        const fCat = el('select', { className: 'adw-select' },
          el('option', { value: 'login', text: 'Login' }),
          el('option', { value: 'seed', text: 'Crypto Seed' }),
          el('option', { value: 'note', text: 'Secure Note' })
        );
        const fUser = el('input', { type: 'text', className: 'adw-entry', placeholder: 'Username (optional)' });
        const fUrl = el('input', { type: 'text', className: 'adw-entry mono', placeholder: 'URL / .onion (optional)' });
        const fSecret = el('input', { type: 'text', className: 'adw-entry mono', placeholder: 'Password, seed, or secret...', required: true });
        const fTotp = el('input', { type: 'text', className: 'adw-entry mono', placeholder: 'Optional TOTP Base32 secret or otpauth:// URI' });
        const totpPreviewBadge = el('span', { className: 'adw-pill-badge info mono', hidden: true });

        createPanel = el('form', {
          className: 'adw-card',
          hidden: true,
          onSubmit: async (e) => {
            e.preventDefault();
            try {
              await apiFetch('/api/vault/items', {
                method: 'POST',
                body: {
                  title: fTitle.value.trim(),
                  category: fCat.value,
                  username: fUser.value.trim() || undefined,
                  url: fUrl.value.trim() || undefined,
                  content: fSecret.value,
                  totpSecret: fTotp.value.trim() || undefined,
                },
              });
              fTitle.value = '';
              fUser.value = '';
              fUrl.value = '';
              fSecret.value = '';
              fTotp.value = '';
              totpPreviewBadge.hidden = true;
              createPanel.hidden = true;
              pushToast('Record sealed in post-quantum OTPQCV2 vault.');
              loadVaultAndTotp();
            } catch (err) {
              pushToast(`Save error: ${err.message}`, true);
            }
          },
        },
          el('strong', { text: 'New Post-Quantum Vault Entry' }),
          el('div', { className: 'grid-2' }, fTitle, fCat),
          el('div', { className: 'grid-2' }, fUser, fUrl),
          el('div', { className: 'adw-row-group' },
            el('div', { style: { flex: '1' } }, fSecret),
            el('button', {
              type: 'button',
              className: 'adw-btn adw-btn-sm',
              onClick: async () => {
                const g = await apiFetch('/api/pqc/generate-secret', { method: 'POST', body: { mode: 'password', length: 28 } });
                fSecret.value = g.secret || '';
              },
            }, 'Gen Password'),
            el('button', {
              type: 'button',
              className: 'adw-btn adw-btn-sm',
              onClick: async () => {
                const g = await apiFetch('/api/pqc/generate-secret', { method: 'POST', body: { mode: 'passphrase', length: 6 } });
                fSecret.value = g.secret || '';
              },
            }, 'Gen Passphrase')
          ),
          el('div', { className: 'adw-row-group' },
            el('div', { style: { flex: '1' } }, fTotp),
            el('button', {
              type: 'button',
              className: 'adw-btn adw-btn-sm',
              onClick: async () => {
                if (!fTotp.value.trim()) return;
                try {
                  const p = await apiFetch('/api/totp/preview', { method: 'POST', body: { secret: fTotp.value.trim() } });
                  totpPreviewBadge.textContent = `Valid TOTP: ${p.code} (${p.remainingSecs}s)`;
                  totpPreviewBadge.hidden = false;
                } catch (err) {
                  pushToast(`Invalid TOTP key: ${err.message}`, true);
                }
              },
            }, 'Verify 2FA'),
            totpPreviewBadge
          ),
          el('div', { className: 'adw-row-group', style: { justifyContent: 'flex-end' } },
            el('button', { type: 'button', className: 'adw-btn adw-btn-sm', onClick: () => { createPanel.hidden = true; }, text: 'Cancel' }),
            el('button', { type: 'submit', className: 'adw-btn adw-btn-sm adw-btn-suggested', text: 'Seal into Vault' })
          )
        );

        listWrap = el('div', { style: { display: 'flex', flexDirection: 'column', gap: '10px' } });
        const rightPane = el('div', { className: 'adw-page-pad' }, createPanel, listWrap);
        ctx.root.appendChild(el('div', { className: 'adw-split-view' }, sidebar, rightPane));
      },
      onOpen() {
        loadVaultAndTotp();
        if (!totpInterval) totpInterval = window.setInterval(refreshTotpOnly, 3000);
      },
      onClose() {
        if (totpInterval) {
          window.clearInterval(totpInterval);
          totpInterval = null;
        }
      },
    });
  }

  /* 6. Text & Notes Editor (Dual-Root RAM + Vault + .otseal Export) */
  function registerEditorApp(wm) {
    let rootSelect = null;
    let pathInput = null;
    let area = null;
    let statusLine = null;

    function updateEditorStats(extra = '') {
      const txt = area.value || '';
      const lines = txt.split('\n').length;
      const bytes = new TextEncoder().encode(txt).length;
      statusLine.textContent = `Lines: ${lines}  |  Size: ${formatBytes(bytes)}  |  Target: ${rootSelect.value}:${pathInput.value}${extra ? '  |  ' + extra : ''}`;
    }

    async function openTargetFile(root, path) {
      rootSelect.value = root;
      pathInput.value = path;
      try {
        const res = await apiFetch(`/api/files/read?root=${encodeURIComponent(root)}&path=${encodeURIComponent(path)}`);
        area.value = res.text ?? '';
        updateEditorStats('Loaded');
      } catch {
        area.value = '';
        updateEditorStats('New Buffer');
      }
    }

    wm.registerApp({
      ...APP_CATALOG[5],
      defaultWidth: 800,
      defaultHeight: 540,
      defaultLeft: 120,
      defaultTop: 36,
      buildContent(ctx) {
        rootSelect = el('select', { className: 'adw-select', style: { width: '115px', height: '28px', padding: '0 8px' } },
          el('option', { value: 'ram', text: 'RAM tmpfs' }),
          el('option', { value: 'vault', text: 'Vault PQC' })
        );
        pathInput = el('input', {
          type: 'text',
          className: 'adw-entry mono',
          style: { width: '220px', height: '28px' },
          value: '/Documents/notes.md',
        });

        ctx.startSlot.append(
          rootSelect,
          pathInput,
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            onClick: () => openTargetFile(rootSelect.value, pathInput.value.trim() || '/Documents/notes.md'),
          }, 'Open')
        );

        ctx.endSlot.append(
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm adw-btn-suggested',
            onClick: async () => {
              const p = pathInput.value.trim() || '/Documents/notes.md';
              const dirIdx = p.lastIndexOf('/');
              if (dirIdx > 0) {
                await apiFetch('/api/files/mkdir', { method: 'POST', body: { root: rootSelect.value, path: p.slice(0, dirIdx) } }).catch(() => {});
              }
              try {
                await apiFetch('/api/files/write', {
                  method: 'POST',
                  body: { root: rootSelect.value, path: p, text: area.value },
                });
                updateEditorStats('Saved');
                pushToast(`Saved ${rootSelect.value}:${p}`);
                pollSystemTelemetry();
              } catch (err) {
                pushToast(`Save failed: ${err.message}`, true);
              }
            },
          }, 'Save'),
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            onClick: async () => {
              const p = pathInput.value.trim() || '/Documents/notes.md';
              try {
                await apiFetch('/api/files/write', { method: 'POST', body: { root: rootSelect.value, path: p, text: area.value } });
                const r = await apiFetch('/api/files/action', { method: 'POST', body: { root: rootSelect.value, path: p, action: 'seal' } });
                pushToast(`Exported hybrid PQC envelope -> ${r.outputPath || p + '.otseal'}`);
              } catch (err) {
                pushToast(`Export .otseal failed: ${err.message}`, true);
              }
            },
          }, window.OnionIcons.createSymbolic('lock', 13), 'Export .otseal')
        );

        area = el('textarea', {
          className: 'adw-textarea mono',
          style: { flex: '1', border: '0', borderRadius: '0', padding: '16px', background: '#1b1b1d', fontSize: '13px', lineHeight: '1.55' },
          placeholder: '# Sovereign Amnesic Buffer\nWrite notes in volatile RAM (/home/onion) or seal directly into /vault/files...',
          onInput: () => updateEditorStats('Modified'),
        });

        statusLine = el('div', {
          className: 'adw-toolbar tabular',
          style: { fontSize: '11.5px', color: 'var(--text-muted)' },
          text: 'Lines: 1  |  Size: 0 B',
        });

        ctx.root.append(area, statusLine);
      },
      onOpen(payload) {
        if (payload && payload.path) {
          openTargetFile(payload.root || 'ram', payload.path);
        } else {
          updateEditorStats();
        }
      },
    });
  }

  /* 7. Metadata & PQC Studio (MAT2 Cleaner + .otseal Studio + Offline QR) */
  function registerCleanerStudioApp(wm) {
    wm.registerApp({
      ...APP_CATALOG[6],
      defaultWidth: 860,
      defaultHeight: 560,
      defaultLeft: 100,
      defaultTop: 28,
      buildContent(ctx) {
        const matPane = el('div', { className: 'adw-page-pad' });
        const pqcPane = el('div', { className: 'adw-page-pad', hidden: true });
        const qrPane = el('div', { className: 'adw-page-pad', hidden: true });

        const tabs = [
          { label: 'MAT2 Cleaner', pane: matPane },
          { label: 'PQC .otseal', pane: pqcPane },
          { label: 'Offline QR', pane: qrPane },
        ];
        const switcher = el('div', { className: 'adw-view-switcher' });
        const tabBtns = tabs.map((t, idx) => {
          const b = el('button', {
            type: 'button',
            className: idx === 0 ? 'adw-switcher-btn is-active' : 'adw-switcher-btn',
            text: t.label,
            onClick: () => {
              tabs.forEach((x, j) => {
                x.pane.hidden = j !== idx;
                tabBtns[j].classList.toggle('is-active', j === idx);
              });
            },
          });
          switcher.appendChild(b);
          return b;
        });
        ctx.centerSlot.replaceChildren(switcher);

        // Pane 1: MAT2 Scrubber
        let pendingFile = null;
        let lastClean = null;
        const fileLabel = el('span', { text: 'Drop JPEG, PNG, PDF, WAV, or MP3 (<= 20 MiB) to strip forensic EXIF/XMP/GPS/ID3 tags in RAM.' });
        const scrubOut = el('div', { className: 'adw-card', hidden: true });
        const fInput = el('input', {
          type: 'file',
          accept: '.jpg,.jpeg,.png,.pdf,.wav,.mp3',
          onChange: () => {
            if (fInput.files && fInput.files[0]) {
              pendingFile = fInput.files[0];
              fileLabel.textContent = `Selected: ${pendingFile.name} (${formatBytes(pendingFile.size)})`;
            }
          },
        });

        matPane.append(
          el('div', {
            className: 'adw-card',
            onDragOver: (e) => e.preventDefault(),
            onDrop: (e) => {
              e.preventDefault();
              if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
                pendingFile = e.dataTransfer.files[0];
                fileLabel.textContent = `Selected: ${pendingFile.name} (${formatBytes(pendingFile.size)})`;
              }
            },
          },
            el('strong', { text: 'Pure-Rust Binary Metadata Sanitizer' }),
            fileLabel,
            el('div', { className: 'adw-row-group' },
              fInput,
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-suggested',
                onClick: async () => {
                  if (!pendingFile) { pushToast('Select a file first.', true); return; }
                  try {
                    const dataB64 = await readFileBase64(pendingFile);
                    const res = await apiFetch('/api/forensics/scrub', {
                      method: 'POST',
                      body: { filename: pendingFile.name, dataB64 },
                    });
                    lastClean = { filename: pendingFile.name, ...res };
                    scrubOut.replaceChildren(
                      el('div', { className: 'qs-header' },
                        el('span', { className: 'adw-pill-badge ok', text: `${String(res.format || '').toUpperCase()} SANITIZED` }),
                        el('button', {
                          type: 'button',
                          className: 'adw-btn adw-btn-sm adw-btn-suggested',
                          onClick: () => {
                            const bin = window.atob(res.cleanB64);
                            const bytes = new Uint8Array(bin.length);
                            for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
                            const url = URL.createObjectURL(new Blob([bytes]));
                            const a = el('a', { href: url, download: `clean_${lastClean.filename}` });
                            document.body.appendChild(a);
                            a.click();
                            a.remove();
                            window.setTimeout(() => URL.revokeObjectURL(url), 1000);
                          },
                        }, window.OnionIcons.createSymbolic('download', 14), 'Download Clean File')
                      ),
                      el('div', { className: 'mono', style: { fontSize: '12px' }, text: `Original: ${formatBytes(res.originalBytes)}  ->  Clean: ${formatBytes(res.cleanBytes)}` }),
                      el('div', { className: 'mono', style: { fontSize: '11.5px', wordBreak: 'break-all' }, text: `SHA-256 Before: ${res.sha256Before}` }),
                      el('div', { className: 'mono', style: { fontSize: '11.5px', wordBreak: 'break-all' }, text: `SHA-256 After:  ${res.sha256After}` }),
                      el('div', { className: 'adw-row-group' },
                        ...(res.removedSegments && res.removedSegments.length
                          ? res.removedSegments.map((s) => el('span', { className: 'adw-pill-badge warn mono', text: s }))
                          : [el('span', { className: 'adw-pill-badge ok', text: 'Zero metadata segments detected' })])
                      )
                    );
                    scrubOut.hidden = false;
                  } catch (err) {
                    pushToast(`Scrub failed: ${err.message}`, true);
                  }
                },
              }, 'Scrub Metadata')
            )
          ),
          scrubOut
        );

        // Pane 2: PQC Envelope Studio
        const recMlkem = el('input', { type: 'text', className: 'adw-entry mono', placeholder: 'Recipient ML-KEM-768 hex (leave blank for self)...' });
        const recX25519 = el('input', { type: 'text', className: 'adw-entry mono', placeholder: 'Recipient X25519 hex (leave blank for self)...' });
        const sealPlain = el('textarea', { className: 'adw-textarea mono', placeholder: 'Plaintext message to seal...' });
        const sealArmor = el('textarea', { className: 'adw-textarea mono', placeholder: '-----BEGIN ONIONOS PQC SEAL-----' });
        const openVerifyBadge = el('span', { className: 'adw-pill-badge mono', hidden: true });
        const openOut = el('textarea', { className: 'adw-textarea mono', readonly: true, placeholder: 'Decrypted output...' });

        pqcPane.append(
          el('div', { className: 'adw-row-group' },
            el('button', { type: 'button', className: 'adw-btn adw-btn-sm', onClick: () => copyClipboard(state.mlkemPubkeyHex, 'ML-KEM-768 Public Key') }, 'Copy Own ML-KEM-768'),
            el('button', { type: 'button', className: 'adw-btn adw-btn-sm', onClick: () => copyClipboard(state.x25519PubkeyHex, 'X25519 Public Key') }, 'Copy Own X25519'),
            el('button', {
              type: 'button',
              className: 'adw-btn adw-btn-sm',
              onClick: () => { recMlkem.value = state.mlkemPubkeyHex; recX25519.value = state.x25519PubkeyHex; },
            }, 'Fill Own Keys')
          ),
          el('div', { className: 'grid-2' },
            el('div', { className: 'adw-card' },
              el('strong', { text: 'Seal Hybrid .otseal' }),
              recMlkem,
              recX25519,
              sealPlain,
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-suggested',
                onClick: async () => {
                  try {
                    const res = await apiFetch('/api/pqc/seal', {
                      method: 'POST',
                      body: {
                        recipientMlkemHex: recMlkem.value.trim() || state.mlkemPubkeyHex,
                        recipientX25519Hex: recX25519.value.trim() || state.x25519PubkeyHex,
                        plaintext: sealPlain.value,
                      },
                    });
                    sealArmor.value = res.envelope || '';
                    pushToast('Sealed with ML-KEM-768 + X25519 + Dual-AEAD.');
                  } catch (err) {
                    pushToast(`Seal error: ${err.message}`, true);
                  }
                },
              }, 'Encapsulate & Sign')
            ),
            el('div', { className: 'adw-card' },
              el('strong', { text: 'Open & Verify .otseal' }),
              sealArmor,
              el('button', {
                type: 'button',
                className: 'adw-btn',
                onClick: async () => {
                  try {
                    const res = await apiFetch('/api/pqc/open', { method: 'POST', body: { envelope: sealArmor.value.trim() } });
                    openOut.value = res.plaintext ?? '';
                    const isVerified = res.verified === true;
                    const verdict = isVerified
                      ? 'Decapsulated (Ed25519 Signature Verified)'
                      : 'Decapsulated (Unsigned / Anonymous Envelope)';
                    openVerifyBadge.textContent =
                      isVerified && res.senderFingerprint
                        ? `${verdict} — Sender ${shortHex(res.senderFingerprint, 6)}`
                        : verdict;
                    openVerifyBadge.className = isVerified ? 'adw-pill-badge ok mono' : 'adw-pill-badge warn mono';
                    openVerifyBadge.hidden = false;
                    pushToast(verdict);
                  } catch (err) {
                    pushToast(`Open error: ${err.message}`, true);
                  }
                },
              }, 'Decapsulate'),
              openVerifyBadge,
              openOut
            )
          )
        );

        // Pane 3: Offline QR Studio
        const qrInput = el('textarea', { className: 'adw-textarea mono', placeholder: 'Enter .onion URL, fingerprint, or text (100% airgapped SVG generation)...' });
        const qrPreview = el('div', { className: 'qr-box', hidden: true });
        let lastQrSvg = '';
        qrPane.append(
          el('div', { className: 'adw-card' },
            el('strong', { text: '100% Airgapped Vector QR Generator' }),
            qrInput,
            el('div', { className: 'adw-row-group' },
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-suggested',
                onClick: async () => {
                  if (!qrInput.value.trim()) return;
                  try {
                    const res = await apiFetch('/api/qr/svg', { method: 'POST', body: { text: qrInput.value.trim() } });
                    lastQrSvg = res.svg || '';
                    qrPreview.replaceChildren(window.OnionIcons.parseSafeSvg(lastQrSvg));
                    qrPreview.hidden = false;
                  } catch (err) {
                    pushToast(`QR error: ${err.message}`, true);
                  }
                },
              }, 'Generate Offline QR'),
              el('button', {
                type: 'button',
                className: 'adw-btn',
                onClick: () => {
                  if (!lastQrSvg) return;
                  const url = URL.createObjectURL(new Blob([lastQrSvg], { type: 'image/svg+xml' }));
                  const a = el('a', { href: url, download: 'onionos-qr.svg' });
                  document.body.appendChild(a);
                  a.click();
                  a.remove();
                  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
                },
              }, 'Download .svg')
            ),
            qrPreview
          )
        );

        ctx.root.append(matPane, pqcPane, qrPane);
      },
    });
  }

  /* 8. Tor Network & OSINT Lab (GET /api/tor/circuits + NEWNYM + OSINT) */
  function registerNetworkLabApp(wm) {
    let circuitsBox = null;
    let bootstrapBadge = null;

    async function loadCircuits() {
      if (state.locked) return;
      try {
        const res = await apiFetch('/api/tor/circuits');
        bootstrapBadge.textContent = `Bootstrap ${res.bootstrapPct ?? 100}%  |  SOCKS ${res.socksOk ? 'OK' : 'WAIT'}`;
        circuitsBox.replaceChildren();
        const circuits = Array.isArray(res.circuits) ? res.circuits : [];
        if (circuits.length === 0) {
          circuitsBox.appendChild(el('div', { style: { color: 'var(--text-muted)', fontSize: '12.5px' }, text: 'Tor daemon active; circuits build automatically on stream demand.' }));
          return;
        }
        for (const c of circuits.slice(0, 8)) {
          const hops = Array.isArray(c.hops) ? c.hops : [];
          circuitsBox.appendChild(
            el('div', { className: 'adw-action-row', style: { flexWrap: 'wrap' } },
              el('div', { className: 'adw-row-group' },
                el('span', { className: 'adw-pill-badge ok mono', text: `#${c.id} ${c.status || 'BUILT'}` }),
                el('span', { className: 'mono', style: { fontSize: '11.5px', color: 'var(--text-muted)' }, text: c.purpose || 'GENERAL' })
              ),
              el('div', { className: 'circuit-hops' },
                ...(hops.length
                  ? hops.map((h, i) => el('span', { className: 'circuit-node', text: `${i === 0 ? 'Guard: ' : i === hops.length - 1 ? 'Exit: ' : 'Middle: '}${h}` }))
                  : [el('span', { className: 'circuit-node', text: 'Encrypted Relay Path' })])
              )
            )
          );
        }
      } catch (err) {
        bootstrapBadge.textContent = `Circuit status: ${err.message}`;
      }
    }

    wm.registerApp({
      ...APP_CATALOG[7],
      defaultWidth: 900,
      defaultHeight: 580,
      defaultLeft: 66,
      defaultTop: 24,
      buildContent(ctx) {
        bootstrapBadge = el('span', { className: 'adw-pill-badge ok tabular', text: 'Bootstrap --%' });
        ctx.startSlot.appendChild(bootstrapBadge);
        ctx.endSlot.append(
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            onClick: loadCircuits,
          }, window.OnionIcons.createSymbolic('refresh', 13), 'Refresh'),
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm adw-btn-suggested',
            onClick: async () => {
              try {
                await apiFetch('/api/tor/newnym', { method: 'POST', body: {} });
                pushToast('SIGNAL NEWNYM sent — fresh Tor identity circuits requested.');
                window.setTimeout(loadCircuits, 700);
              } catch (err) {
                pushToast(`NEWNYM failed: ${err.message}`, true);
              }
            },
          }, 'New Identity (NEWNYM)')
        );

        circuitsBox = el('div', { className: 'adw-boxed-list' });

        // v3 Validator
        const onionIn = el('input', {
          type: 'text',
          className: 'adw-entry mono',
          value: 'duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion',
        });
        const onionOut = el('div', { className: 'mono', style: { fontSize: '12px', color: 'var(--text-secondary)', wordBreak: 'break-all' } });

        // Isolated Probe
        const probeIn = el('input', {
          type: 'text',
          className: 'adw-entry mono',
          placeholder: 'http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion',
        });
        const probeOut = el('div', { className: 'mono', style: { fontSize: '12px', maxHeight: '150px', overflowY: 'auto' } });

        ctx.root.appendChild(
          el('div', { className: 'adw-page-pad' },
            el('div', { className: 'adw-card' },
              el('strong', { text: 'Live Tor Circuits (ControlPort GETINFO circuit-status)' }),
              circuitsBox
            ),
            el('div', { className: 'grid-2' },
              el('form', {
                className: 'adw-card',
                onSubmit: async (e) => {
                  e.preventDefault();
                  try {
                    const r = await apiFetch('/api/osint/validate-onion', { method: 'POST', body: { address: onionIn.value.trim() } });
                    const pk = r.pubkeyHex || r.ed25519PubkeyHex || '--';
                    onionOut.textContent = `${r.valid ? 'VALID v3' : 'INVALID'} | PubKey: ${shortHex(pk, 12)} | ${r.reason || 'SHA3-256 checksum verified'}`;
                  } catch (err) {
                    pushToast(`Validate error: ${err.message}`, true);
                  }
                },
              },
                el('strong', { text: '.onion v3 Math Checksum Validator' }),
                onionIn,
                el('button', { type: 'submit', className: 'adw-btn adw-btn-suggested', text: 'Verify Ed25519 + SHA3-256' }),
                onionOut
              ),
              el('form', {
                className: 'adw-card',
                onSubmit: async (e) => {
                  e.preventDefault();
                  if (!probeIn.value.trim()) return;
                  probeOut.textContent = 'Probing over stream-isolated SOCKS5h circuit...';
                  try {
                    const r = await apiFetch('/api/osint/probe', { method: 'POST', body: { url: probeIn.value.trim() } });
                    probeOut.replaceChildren(
                      el('div', { text: `Status: HTTP ${r.statusCode ?? '--'}  |  Latency: ${r.latencyMs ?? 0} ms  |  Circuit: ${r.circuitIsolationId || 'iso'}` }),
                      ...Object.entries({ ...(r.securityHeaders || {}), ...(r.rawHeaders || {}) })
                        .slice(0, 12)
                        .map(([k, v]) => el('div', { style: { color: 'var(--text-muted)' }, text: `${k}: ${v}` }))
                    );
                  } catch (err) {
                    probeOut.textContent = `Probe error: ${err.message}`;
                  }
                },
              },
                el('strong', { text: 'Stream-Isolated Header Probe' }),
                probeIn,
                el('button', { type: 'submit', className: 'adw-btn adw-btn-suggested', text: 'Execute Isolated Probe' }),
                probeOut
              )
            )
          )
        );
      },
      onOpen() {
        loadCircuits();
      },
    });
  }

  /* 9. Console (GNOME Console kgx Multi-Tab PTY) */
  function registerConsoleApp(wm) {
    const tabs = [];
    let activeTabId = 0;
    let tabSeq = 0;
    let tabBar = null;
    let screenEl = null;
    let cmdInput = null;

    function activeTab() {
      return tabs.find((t) => t.id === activeTabId) || tabs[0] || null;
    }

    function resizeActivePty() {
      const t = activeTab();
      if (!t || !t.ws || t.ws.readyState !== WebSocket.OPEN || !screenEl) return;
      const cols = Math.max(60, Math.floor((screenEl.clientWidth || 640) / 7.6));
      const rows = Math.max(18, Math.floor((screenEl.clientHeight || 320) / 19));
      t.ws.send(JSON.stringify({ type: 'resize', cols, rows }));
    }

    state.appHooks.resizeTerminal = resizeActivePty;

    function renderTabs() {
      tabBar.replaceChildren();
      for (const t of tabs) {
        tabBar.appendChild(
          el('div', { className: t.id === activeTabId ? 'kgx-tab is-active' : 'kgx-tab' },
            el('span', {
              onClick: () => {
                activeTabId = t.id;
                renderTabs();
                screenEl.textContent = t.buffer;
                screenEl.scrollTop = screenEl.scrollHeight;
                resizeActivePty();
              },
              text: t.title,
            }),
            tabs.length > 1
              ? el('button', {
                  type: 'button',
                  className: 'adw-btn-flat',
                  style: { border: '0', color: 'inherit', cursor: 'pointer', padding: '0 2px' },
                  onClick: () => closePtyTab(t.id),
                }, 'x')
              : null
          )
        );
      }
      tabBar.appendChild(
        el('button', { type: 'button', className: 'adw-btn adw-btn-sm', onClick: () => spawnPtyTab() },
          window.OnionIcons.createSymbolic('plus', 12), 'New Tab'
        )
      );
    }

    function spawnPtyTab() {
      if (state.locked) return;
      tabSeq += 1;
      const t = {
        id: tabSeq,
        title: `Shell #${tabSeq}`,
        buffer: `[GNOME Console — Amnesic PTY #${tabSeq} @ /home/onion]\n`,
        ws: null,
      };
      tabs.push(t);
      activeTabId = t.id;

      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${proto}//${window.location.host}/api/pty/ws`);
      t.ws = ws;

      ws.addEventListener('open', () => {
        resizeActivePty();
        pollSystemTelemetry();
      });
      ws.addEventListener('message', (ev) => {
        let chunk = '';
        try {
          const msg = JSON.parse(ev.data);
          chunk = msg.type === 'output' ? msg.data : msg.error ? `\n[Error] ${msg.error}\n` : '';
        } catch {
          chunk = String(ev.data);
        }
        t.buffer = (t.buffer + stripAnsi(chunk)).slice(-65536);
        if (t.id === activeTabId && screenEl) {
          screenEl.textContent = t.buffer;
          screenEl.scrollTop = screenEl.scrollHeight;
        }
      });
      ws.addEventListener('close', () => {
        t.buffer += '\n[Session exited]\n';
        if (t.id === activeTabId && screenEl) screenEl.textContent = t.buffer;
      });

      renderTabs();
      if (screenEl) screenEl.textContent = t.buffer;
    }

    function closePtyTab(id) {
      const idx = tabs.findIndex((x) => x.id === id);
      if (idx < 0) return;
      if (tabs[idx].ws) {
        try { tabs[idx].ws.close(); } catch { /* ignore */ }
      }
      tabs.splice(idx, 1);
      if (tabs.length === 0) return;
      activeTabId = tabs[tabs.length - 1].id;
      renderTabs();
      screenEl.textContent = activeTab().buffer;
    }

    function sendToActive(data) {
      const t = activeTab();
      if (!t || !t.ws || t.ws.readyState !== WebSocket.OPEN) {
        spawnPtyTab();
        window.setTimeout(() => {
          const nt = activeTab();
          if (nt && nt.ws && nt.ws.readyState === WebSocket.OPEN) {
            nt.ws.send(JSON.stringify({ type: 'input', data }));
          }
        }, 250);
        return;
      }
      t.ws.send(JSON.stringify({ type: 'input', data }));
    }

    wm.registerApp({
      ...APP_CATALOG[8],
      defaultWidth: 780,
      defaultHeight: 500,
      defaultLeft: 132,
      defaultTop: 42,
      buildContent(ctx) {
        const quickCmds = ['onion-os --self-test', 'onion-pqc keygen', 'gpg --version', 'ls -la'];
        const quickBar = el('div', { className: 'adw-toolbar', style: { background: '#1c1924' } },
          el('div', { className: 'adw-row-group' },
            ...quickCmds.map((cmd) =>
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-sm mono',
                onClick: () => sendToActive(`${cmd}\n`),
              }, cmd)
            )
          ),
          el('div', { className: 'adw-row-group' },
            el('button', { type: 'button', className: 'adw-btn adw-btn-sm', onClick: () => sendToActive('\x03') }, 'Ctrl+C'),
            el('button', { type: 'button', className: 'adw-btn adw-btn-sm', onClick: () => spawnPtyTab() }, 'Reconnect')
          )
        );

        tabBar = el('div', { className: 'kgx-tabbar' });
        screenEl = el('pre', { className: 'kgx-screen', tabindex: '0' });
        cmdInput = el('input', {
          type: 'text',
          className: 'adw-entry mono',
          placeholder: 'Type command and press Enter...',
          autocomplete: 'off',
          spellcheck: 'false',
        });

        const form = el('form', {
          className: 'kgx-input-row',
          onSubmit: (e) => {
            e.preventDefault();
            const v = cmdInput.value;
            cmdInput.value = '';
            sendToActive(`${v}\n`);
          },
        },
          el('span', { className: 'mono', style: { color: '#8ff0a4', fontWeight: '700' }, text: 'onion@sovereign:~$' }),
          cmdInput,
          el('button', { type: 'submit', className: 'adw-btn adw-btn-sm adw-btn-suggested', text: 'Run' })
        );

        ctx.root.append(tabBar, quickBar, screenEl, form);
      },
      onOpen() {
        if (tabs.length === 0) spawnPtyTab();
        cmdInput.focus();
      },
      onClose() {
        while (tabs.length > 0) {
          const t = tabs.pop();
          if (t.ws) { try { t.ws.close(); } catch { /* ignore */ } }
        }
      },
    });
  }

  /* 10. System Monitor & Settings (Resources, Security Badges, Processes & GNOME Appearance) */
  function registerSettingsApp(wm) {
    let monitorTimer = null;
    let kpiRow = null;
    let badgesRow = null;
    let procTbody = null;
    let autoLockSelect = null;
    let compactCheck = null;
    const wpButtons = [];

    async function refreshMonitor() {
      if (state.locked) return;
      try {
        const [m, a] = await Promise.all([
          apiFetch('/api/system/monitor'),
          apiFetch('/api/forensics/audit').catch(() => ({})),
        ]);

        kpiRow.replaceChildren(
          el('div', { className: 'adw-card' },
            el('span', { style: { fontSize: '11.5px', color: 'var(--text-muted)' }, text: 'Container RSS Memory' }),
            el('strong', { className: 'tabular', style: { fontSize: '20px' }, text: formatKib(m.memRssKib) })
          ),
          el('div', { className: 'adw-card' },
            el('span', { style: { fontSize: '11.5px', color: 'var(--text-muted)' }, text: 'Amnesic tmpfs (/home/onion)' }),
            el('strong', { className: 'tabular', style: { fontSize: '20px' }, text: `${formatBytes(m.tmpfsBytes)} (${m.tmpfsFiles ?? 0} files)` })
          ),
          el('div', { className: 'adw-card' },
            el('span', { style: { fontSize: '11.5px', color: 'var(--text-muted)' }, text: 'Runtime Uptime & UID' }),
            el('strong', { className: 'tabular', style: { fontSize: '20px' }, text: `${formatUptime(m.uptimeSecs)} | UID ${m.uid ?? 10014}` })
          )
        );

        const secChecks = [
          { label: `CapEff=${m.capEffHex || '0000000000000000'}`, ok: !m.capEffHex || /^0+$/.test(m.capEffHex) },
          { label: `CapBnd=${m.capBndHex || '0000000000000000'}`, ok: Boolean(a.capBndZero ?? true) },
          { label: `NoNewPrivs=${m.noNewPrivs ? 1 : 0}`, ok: Boolean(m.noNewPrivs ?? a.noNewPrivs) },
          { label: 'Netfilter UID-Lock', ok: Boolean(m.netfilterActive ?? true) },
          { label: 'PR_SET_DUMPABLE=0', ok: Boolean(a.dumpableZero ?? true) },
          { label: 'Read-Only RootFS', ok: Boolean(a.rootfsReadonly ?? true) },
        ];
        badgesRow.replaceChildren(
          ...secChecks.map((c) => el('span', { className: c.ok ? 'adw-pill-badge ok mono' : 'adw-pill-badge warn mono', text: c.label }))
        );

        procTbody.replaceChildren();
        for (const p of m.processes || []) {
          procTbody.appendChild(
            el('tr', {},
              el('td', { className: 'tabular', text: p.pid }),
              el('td', { className: 'mono', text: p.name }),
              el('td', { text: p.state || 'S' }),
              el('td', { className: 'tabular', text: formatKib(p.memKib) })
            )
          );
        }
      } catch (err) {
        pushToast(`Monitor error: ${err.message}`, true);
      }
    }

    state.appHooks.syncSettingsForm = () => {
      if (autoLockSelect) autoLockSelect.value = String(state.settings.autoLockMinutes);
      if (compactCheck) compactCheck.checked = Boolean(state.settings.dockCompact);
      wpButtons.forEach((b) => b.el.classList.toggle('is-selected', b.wp === state.settings.wallpaper));
    };

    wm.registerApp({
      ...APP_CATALOG[9],
      defaultWidth: 850,
      defaultHeight: 560,
      defaultLeft: 92,
      defaultTop: 30,
      buildContent(ctx) {
        const resPane = el('div', { className: 'adw-page-pad' });
        const appPane = el('div', { className: 'adw-page-pad', hidden: true });

        const b1 = el('button', {
          type: 'button',
          className: 'adw-switcher-btn is-active',
          text: 'Resources & Security',
          onClick: () => { resPane.hidden = false; appPane.hidden = true; b1.classList.add('is-active'); b2.classList.remove('is-active'); },
        });
        const b2 = el('button', {
          type: 'button',
          className: 'adw-switcher-btn',
          text: 'Appearance & Privacy',
          onClick: () => { appPane.hidden = false; resPane.hidden = true; b2.classList.add('is-active'); b1.classList.remove('is-active'); },
        });
        ctx.centerSlot.replaceChildren(el('div', { className: 'adw-view-switcher' }, b1, b2));
        ctx.endSlot.appendChild(
          el('button', { type: 'button', className: 'adw-btn adw-btn-sm', onClick: refreshMonitor },
            window.OnionIcons.createSymbolic('refresh', 13)
          )
        );

        kpiRow = el('div', { className: 'grid-3' });
        badgesRow = el('div', { className: 'adw-row-group' });
        procTbody = el('tbody');

        resPane.append(
          kpiRow,
          el('div', { className: 'adw-card' },
            el('strong', { text: 'Kernel & Namespace Hardening Posture' }),
            badgesRow
          ),
          el('div', { className: 'adw-card' },
            el('strong', { text: 'Active Container Processes' }),
            el('table', { className: 'adw-table' },
              el('thead', {}, el('tr', {}, el('th', { text: 'PID' }), el('th', { text: 'Process' }), el('th', { text: 'State' }), el('th', { text: 'RSS' }))),
              procTbody
            )
          )
        );

        const wpGrid = el('div', { className: 'wallpaper-swatch-grid' });
        for (const preset of ONION_THEME_PRESETS) {
          const cv = el('canvas', { className: 'mesh-bg-canvas', width: '160', height: '68', 'aria-hidden': 'true' });
          const sw = el('button', {
            type: 'button',
            className: 'wallpaper-swatch',
            'data-wp': preset.id,
            'aria-label': preset.title,
            onClick: () => saveSystemSettings({ wallpaper: preset.id }),
          },
            cv,
            el('span', { className: 'wallpaper-swatch-label', text: preset.title })
          );
          wpButtons.push({ wp: preset.id, el: sw });
          wpGrid.appendChild(sw);
        }

        autoLockSelect = el('select', {
          className: 'adw-select',
          style: { width: '160px' },
          onChange: () => saveSystemSettings({ autoLockMinutes: Number(autoLockSelect.value) }),
        },
          el('option', { value: '5', text: '5 Minutes' }),
          el('option', { value: '15', text: '15 Minutes' }),
          el('option', { value: '30', text: '30 Minutes' }),
          el('option', { value: '0', text: 'Never (Manual)' })
        );

        compactCheck = el('input', {
          type: 'checkbox',
          onChange: () => saveSystemSettings({ dockCompact: compactCheck.checked }),
        });

        appPane.append(
          el('div', { className: 'adw-card' },
            el('strong', { text: 'Onion Mesh Signature Wallpaper' }),
            wpGrid
          ),
          el('div', { className: 'adw-boxed-list' },
            el('div', { className: 'adw-action-row' },
              el('div', {},
                el('span', { className: 'adw-row-title', text: 'Idle Auto-Lock Timeout' }),
                el('span', { className: 'adw-row-sub', text: 'Zeroizes RAM session keys automatically on inactivity' })
              ),
              autoLockSelect
            ),
            el('label', { className: 'adw-action-row', style: { cursor: 'pointer' } },
              el('div', {},
                el('span', { className: 'adw-row-title', text: 'Compact GNOME Dash / Dock' }),
                el('span', { className: 'adw-row-sub', text: 'Reduces dock icon footprint for smaller screens' })
              ),
              compactCheck
            )
          )
        );

        ctx.root.append(resPane, appPane);
        state.appHooks.syncSettingsForm();
      },
      onOpen() {
        refreshMonitor();
        if (!monitorTimer) monitorTimer = window.setInterval(refreshMonitor, 4000);
      },
      onClose() {
        if (monitorTimer) {
          window.clearInterval(monitorTimer);
          monitorTimer = null;
        }
      },
    });
  }

  /* 11. OnionTalk Federated Relay Node Manager (oniontalk-relay-rs v1.8.1) */
  function registerRelayApp(wm) {
    let persistentMode = false;
    let pollTimer = null;
    let currentVoucher = '';

    let stateBadge = null;
    let ramBadge = null;
    let uptimeBadge = null;
    let startBtn = null;
    let stopBtn = null;
    let radioEph = null;
    let radioPers = null;

    let runningWrap = null;
    let onionAddrEl = null;
    let pubkeyEl = null;
    let qrBox = null;
    let voucherBox = null;
    let copyVoucherBtn = null;
    let kpiGrid = null;

    function kpiCell(label, value) {
      return el('div', { className: 'adw-card', style: { padding: '10px 12px', gap: '4px' } },
        el('span', { style: { fontSize: '11.5px', color: 'var(--text-muted)' }, text: label }),
        el('strong', { className: 'tabular mono', style: { fontSize: '14px', wordBreak: 'break-word' }, text: value })
      );
    }

    async function refreshRelayStatus() {
      if (state.locked) return;
      try {
        const s = await apiFetch('/api/relay/status');
        const st = s.state || 'stopped';

        if (st === 'running') {
          stateBadge.textContent = 'Running — Federated Mesh Active';
          stateBadge.className = 'adw-pill-badge ok';
        } else if (st === 'starting') {
          stateBadge.textContent = 'Starting...';
          stateBadge.className = 'adw-pill-badge warn';
        } else {
          stateBadge.textContent = 'Stopped';
          stateBadge.className = 'adw-pill-badge';
        }

        ramBadge.textContent = `RAM: ${formatKib(s.memoryKib ?? 0)}`;
        uptimeBadge.textContent = `Up: ${formatUptime(s.uptimeSecs ?? 0)}`;

        const isBusy = st === 'running' || st === 'starting';
        startBtn.disabled = isBusy || s.binaryAvailable === false;
        stopBtn.disabled = st === 'stopped';
        radioEph.disabled = isBusy;
        radioPers.disabled = isBusy;

        if (isBusy && typeof s.persistent === 'boolean') {
          persistentMode = s.persistent;
          radioEph.checked = !persistentMode;
          radioPers.checked = persistentMode;
        }

        if (st === 'running') {
          runningWrap.hidden = false;
          onionAddrEl.textContent = s.onionAddress || '--';
          pubkeyEl.textContent = s.nodePubkey || '--';

          kpiGrid.replaceChildren(
            kpiCell('Peers Count', String(s.peersCount ?? 0)),
            kpiCell('Online / Hibernating Nodes', `${s.onlineNodes ?? 0} online / ${s.hibernatingNodes ?? 0} hibernating`),
            kpiCell('Avg Peer RTT (ms)', `${s.avgPeerRttMs ?? 0} ms`),
            kpiCell('Anti-Sybil / Spoofed ACKs Blocked', `${s.invalidPeersBlocked ?? 0} invalid / ${s.spoofedAcksBlocked ?? 0} spoofed`),
            kpiCell('Engine', s.engine || 'oniontalk-relay-rs/1.8.1'),
            kpiCell('Routing Engine', s.routingEngine || 'epidemic-gossip-v3'),
            kpiCell('Zero-Trust Suite', s.zeroTrustMode !== false ? 'Zero-Trust Enforced (Ed25519 + OTPQCV2)' : 'Standard')
          );
        } else {
          runningWrap.hidden = true;
          qrBox.hidden = true;
          qrBox.replaceChildren();
          qrBox.dataset.qrTarget = '';
          currentVoucher = '';
          voucherBox.hidden = true;
          voucherBox.textContent = '';
          copyVoucherBtn.hidden = true;
        }
      } catch (err) {
        pushToast(`Relay status error: ${err.message}`, true);
      }
    }

    async function startRelayNode() {
      startBtn.disabled = true;
      stateBadge.textContent = 'Starting...';
      stateBadge.className = 'adw-pill-badge warn';
      try {
        await apiFetch('/api/relay/start', {
          method: 'POST',
          body: { persistent: Boolean(persistentMode) },
        });
        pushToast(
          persistentMode
            ? 'Persistent Sovereign Relay started (/vault/relay.otpqcv2).'
            : 'Ephemeral RAM Federated Relay started (ADD_ONION).'
        );
        await refreshRelayStatus();
        pollSystemTelemetry();
      } catch (err) {
        startBtn.disabled = false;
        pushToast(`Relay start failed: ${err.message}`, true);
        refreshRelayStatus();
      }
    }

    state.appHooks.toggleRelayFromQs = () => {
      wm.open('relay');
      if ((state.telemetry.relayState || 'stopped') === 'stopped') {
        startRelayNode();
      }
    };

    wm.registerApp({
      ...APP_CATALOG[10],
      defaultWidth: 880,
      defaultHeight: 600,
      defaultLeft: 148,
      defaultTop: 24,
      buildContent(ctx) {
        ctx.endSlot.appendChild(
          el('button', {
            type: 'button',
            className: 'adw-btn adw-btn-sm',
            onClick: refreshRelayStatus,
          }, window.OnionIcons.createSymbolic('refresh', 13), 'Refresh Stats')
        );

        stateBadge = el('span', { className: 'adw-pill-badge', text: 'Stopped' });
        ramBadge = el('span', { className: 'adw-pill-badge info tabular', text: 'RAM: 0 KiB' });
        uptimeBadge = el('span', { className: 'adw-pill-badge tabular', text: 'Up: 0s' });

        startBtn = el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-success adw-btn-pill',
          onClick: startRelayNode,
        }, window.OnionIcons.createSymbolic('relay-symbolic', 15), 'Start Federated Relay');

        stopBtn = el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-destructive adw-btn-pill',
          disabled: true,
          onClick: async () => {
            stopBtn.disabled = true;
            try {
              await apiFetch('/api/relay/stop', { method: 'POST', body: {} });
              pushToast('Federated Relay stopped and Hidden Service unlinked (DEL_ONION).');
              await refreshRelayStatus();
              pollSystemTelemetry();
            } catch (err) {
              pushToast(`Relay stop failed: ${err.message}`, true);
              refreshRelayStatus();
            }
          },
        }, window.OnionIcons.createSymbolic('power', 14), 'Stop Relay (DEL_ONION)');

        const hero = el('div', { className: 'relay-hero-banner' },
          el('div', { className: 'adw-row-group', style: { gap: '12px' } },
            window.OnionIcons.createAppIcon('relay', 46),
            el('div', {},
              el('strong', { style: { fontSize: '15px', display: 'block' }, text: 'OnionTalk Federated Relay Node' }),
              el('span', { style: { fontSize: '12px', color: 'var(--text-secondary)' }, text: 'S/Kademlia DHT + GossipSub v1.2 Mesh over Tor ED25519-V3' })
            )
          ),
          el('div', { className: 'adw-row-group' }, stateBadge, ramBadge, uptimeBadge)
        );

        radioEph = el('input', {
          type: 'radio',
          name: 'relay-id-mode',
          checked: true,
          onChange: () => { if (radioEph.checked) persistentMode = false; },
        });
        radioPers = el('input', {
          type: 'radio',
          name: 'relay-id-mode',
          onChange: () => { if (radioPers.checked) persistentMode = true; },
        });

        const modeSelector = el('div', { className: 'adw-boxed-list' },
          el('label', { className: 'adw-action-row', style: { cursor: 'pointer' } },
            el('div', {},
              el('span', { className: 'adw-row-title', text: 'Ephemeral RAM Relay (New .onion each session — wiped on stop)' }),
              el('span', { className: 'adw-row-sub', text: 'Generates disposable ED25519-V3 Hidden Service strictly in volatile memory' })
            ),
            radioEph
          ),
          el('label', { className: 'adw-action-row', style: { cursor: 'pointer' } },
            el('div', {},
              el('span', { className: 'adw-row-title', text: 'Persistent Sovereign Relay (Encrypted in /vault/relay.otpqcv2 — keeps .onion & Kademlia reputation)' }),
              el('span', { className: 'adw-row-sub', text: 'Seals relay identity with ML-KEM-768 + X25519 + Dual-AEAD inside /vault/relay.otpqcv2' })
            ),
            radioPers
          )
        );

        const controlsBar = el('div', { className: 'adw-row-group' }, startBtn, stopBtn);

        onionAddrEl = el('code', { className: 'mono', style: { fontSize: '12.5px', color: 'var(--adw-success-text)', wordBreak: 'break-all' }, text: '--' });
        pubkeyEl = el('code', { className: 'mono', style: { fontSize: '11.5px', color: 'var(--text-secondary)', wordBreak: 'break-all' }, text: '--' });
        qrBox = el('div', { className: 'qr-box', hidden: true });

        const identityCard = el('div', { className: 'adw-card' },
          el('div', { className: 'qs-header' },
            el('strong', { text: '.onion v3 Relay Identity' }),
            el('div', { className: 'adw-row-group' },
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-sm adw-btn-suggested',
                onClick: () => copyClipboard(onionAddrEl.textContent, 'Relay .onion address'),
              }, window.OnionIcons.createSymbolic('copy', 13), 'Copy .onion'),
              el('button', {
                type: 'button',
                className: 'adw-btn adw-btn-sm',
                onClick: async () => {
                  const target = onionAddrEl.textContent;
                  if (!target || target === '--') return;
                  if (!qrBox.hidden && qrBox.dataset.qrTarget === target) {
                    qrBox.hidden = true;
                    return;
                  }
                  try {
                    const qr = await apiFetch('/api/qr/svg', { method: 'POST', body: { text: `http://${target}` } });
                    qrBox.replaceChildren(window.OnionIcons.parseSafeSvg(qr.svg || ''));
                    qrBox.dataset.qrTarget = target;
                    qrBox.hidden = false;
                  } catch (err) {
                    pushToast(`QR generation failed: ${err.message}`, true);
                  }
                },
              }, window.OnionIcons.createSymbolic('qr', 13), 'Show QR Code')
            )
          ),
          el('div', {},
            el('span', { style: { fontSize: '11px', color: 'var(--text-subtle)', display: 'block' }, text: 'Hidden Service Hostname' }),
            onionAddrEl
          ),
          el('div', {},
            el('span', { style: { fontSize: '11px', color: 'var(--text-subtle)', display: 'block' }, text: 'Ed25519 Node Public Key' }),
            pubkeyEl
          ),
          qrBox
        );

        voucherBox = el('div', { className: 'relay-voucher-box', hidden: true });
        copyVoucherBtn = el('button', {
          type: 'button',
          className: 'adw-btn adw-btn-sm adw-btn-success',
          hidden: true,
          onClick: () => copyClipboard(currentVoucher, 'otnode1: Operator Voucher'),
        }, window.OnionIcons.createSymbolic('copy', 13), 'Copy Voucher for OnionTalk');

        const voucherCard = el('div', { className: 'adw-card' },
          el('strong', { text: 'Founder / Operator Voucher (otnode1:)' }),
          el('span', { style: { fontSize: '12px', color: 'var(--text-muted)' },
            text: 'Generate a signed operator token and paste it into the Founder / Relay Node section of OnionTalk v1.8.1 to claim zero-trust relay administration.',
          }),
          el('div', { className: 'adw-row-group' },
            el('button', {
              type: 'button',
              className: 'adw-btn adw-btn-suggested',
              onClick: async () => {
                try {
                  const res = await apiFetch('/api/relay/voucher', { method: 'POST', body: {} });
                  currentVoucher = res.voucher || '';
                  voucherBox.textContent = currentVoucher || 'No voucher returned.';
                  voucherBox.hidden = false;
                  copyVoucherBtn.hidden = !currentVoucher;
                  pushToast('Signed otnode1: operator voucher generated.');
                } catch (err) {
                  pushToast(`Voucher error: ${err.message}`, true);
                }
              },
            }, window.OnionIcons.createSymbolic('key', 14), 'Generate otnode1: Operator Voucher'),
            copyVoucherBtn
          ),
          voucherBox
        );

        kpiGrid = el('div', { className: 'relay-kpi-grid' });
        const telemetrySection = el('div', { className: 'adw-card' },
          el('strong', { text: 'S/Kademlia & GossipSub v1.2 Live Telemetry' }),
          kpiGrid
        );

        runningWrap = el('div', { style: { display: 'flex', flexDirection: 'column', gap: '12px' }, hidden: true },
          el('div', { className: 'grid-2' }, identityCard, voucherCard),
          telemetrySection
        );

        ctx.root.appendChild(
          el('div', { className: 'adw-page-pad' },
            hero,
            modeSelector,
            controlsBar,
            runningWrap
          )
        );
      },
      onOpen() {
        refreshRelayStatus();
        if (!pollTimer) pollTimer = window.setInterval(refreshRelayStatus, 3500);
      },
      onClose() {
        if (pollTimer) {
          window.clearInterval(pollTimer);
          pollTimer = null;
        }
        currentVoucher = '';
        if (voucherBox) {
          voucherBox.textContent = '';
          voucherBox.hidden = true;
        }
        if (copyVoucherBtn) copyVoucherBtn.hidden = true;
      },
    });
  }

  /* ------------------------------------------------------------------------
     Shell Initialization & Global Listeners
     ------------------------------------------------------------------------ */
  function mountShellStaticIcons() {
    $('gdm-avatar').appendChild(window.OnionIcons.createAppIcon('oniontalk', 72));
    $('btn-gdm-eye').appendChild(window.OnionIcons.createSymbolic('eye', 16));
    $('overview-search-ico').appendChild(window.OnionIcons.createSymbolic('search', 16));

    $('top-qs-icons').append(
      window.OnionIcons.createSymbolic('tor', 14),
      window.OnionIcons.createSymbolic('relay-symbolic', 14),
      window.OnionIcons.createSymbolic('shield', 14),
      window.OnionIcons.createSymbolic('sliders', 14)
    );

    $('btn-qs-settings').appendChild(window.OnionIcons.createSymbolic('sliders', 14));
    $('btn-qs-lock').appendChild(window.OnionIcons.createSymbolic('lock', 14));
    $('qs-ico-tor').appendChild(window.OnionIcons.createSymbolic('tor', 18));
    $('qs-ico-browser').appendChild(window.OnionIcons.createSymbolic('globe', 18));
    $('qs-ico-onionshare').appendChild(window.OnionIcons.createSymbolic('share', 18));
    $('qs-ico-firewall').appendChild(window.OnionIcons.createSymbolic('shield', 18));
    $('qs-ico-relay').appendChild(window.OnionIcons.createSymbolic('relay-symbolic', 18));

    // Build Dock & Activities App Grid
    const dock = $('gnome-dock');
    const grid = $('overview-app-grid');

    for (const app of APP_CATALOG) {
      const dockBtn = el('button', {
        type: 'button',
        className: 'dock-item',
        'data-app-id': app.id,
        title: app.title,
        'aria-label': app.title,
        onClick: () => {
          closeShellPopovers();
          state.wm.toggleFromDock(app.id);
        },
      },
        window.OnionIcons.createAppIcon(app.id, 42),
        el('span', { className: 'dock-dot' })
      );
      dock.appendChild(dockBtn);

      grid.appendChild(
        el('button', {
          type: 'button',
          className: 'app-grid-tile',
          onClick: () => {
            closeShellPopovers();
            state.wm.open(app.id);
          },
        },
          window.OnionIcons.createAppIcon(app.id, 64),
          el('span', { className: 'app-grid-label', text: app.title })
        )
      );
    }

    dock.append(
      el('div', { className: 'dock-sep' }),
      el('button', {
        type: 'button',
        className: 'dock-item',
        title: 'Show All Applications',
        'aria-label': 'Show All Applications',
        onClick: () => toggleActivities(),
      }, window.OnionIcons.createSymbolic('sliders', 22))
    );
  }

  function wireShellEvents() {
    // Activity tracker for auto-lock
    ['pointerdown', 'keydown'].forEach((evt) => {
      document.addEventListener(evt, () => { state.lastActivityMs = Date.now(); }, { passive: true });
    });

    state.timers.idle = window.setInterval(() => {
      if (state.locked || !state.settings.autoLockMinutes || state.settings.autoLockMinutes <= 0) return;
      if (Date.now() - state.lastActivityMs > state.settings.autoLockMinutes * 60 * 1000) {
        requestSessionLock();
      }
    }, 15000);

    // GDM Unlock
    $('btn-gdm-eye').addEventListener('click', () => {
      const inp = $('gdm-passphrase');
      const show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      $('btn-gdm-eye').replaceChildren(window.OnionIcons.createSymbolic(show ? 'eye-off' : 'eye', 16));
    });

    $('form-gdm-unlock').addEventListener('submit', async (e) => {
      e.preventDefault();
      const inp = $('gdm-passphrase');
      const err = $('gdm-error');
      const btn = $('btn-gdm-submit');
      const passphrase = inp.value;

      err.hidden = true;
      if (!passphrase || passphrase.length < 12) {
        err.textContent = 'Master passphrase must be at least 12 characters.';
        err.hidden = false;
        inp.focus();
        return;
      }

      btn.disabled = true;
      try {
        const res = await apiFetch('/api/auth/unlock', { method: 'POST', body: { passphrase } });
        inp.value = '';
        state.csrfToken = res.csrfToken || '';
        state.identityFingerprint = res.identityFingerprint || '';
        state.mlkemPubkeyHex = res.mlkemPubkeyHex || '';
        state.x25519PubkeyHex = res.x25519PubkeyHex || '';
        state.ed25519PubkeyHex = res.ed25519PubkeyHex || '';
        enterDesktopSession();
        pushToast('OTPQCV2 post-quantum session unlocked.');
      } catch (ex) {
        err.textContent = ex.message || 'Invalid passphrase.';
        err.hidden = false;
      } finally {
        btn.disabled = false;
      }
    });

    // Top Bar Buttons
    $('btn-activities').addEventListener('click', () => toggleActivities());
    $('btn-focused-app').addEventListener('click', () => {
      const fid = state.wm.getFocusedAppId();
      if (fid) state.wm.focus(fid);
    });

    $('btn-top-clock').addEventListener('click', () => {
      const willOpen = $('calendar-popover').hidden;
      closeShellPopovers();
      if (willOpen) {
        renderCalendar();
        renderNotifications();
        $('calendar-popover').hidden = false;
        $('btn-top-clock').classList.add('is-active');
        $('btn-top-clock').setAttribute('aria-expanded', 'true');
      }
    });

    $('btn-notif-clear').addEventListener('click', () => {
      state.notifications = [];
      renderNotifications();
    });

    $('btn-quick-settings').addEventListener('click', () => {
      const willOpen = $('qs-popover').hidden;
      closeShellPopovers();
      if (willOpen) {
        $('qs-popover').hidden = false;
        $('btn-quick-settings').classList.add('is-active');
        $('btn-quick-settings').setAttribute('aria-expanded', 'true');
      }
    });

    // Quick Settings Actions
    $('btn-qs-settings').addEventListener('click', () => { closeShellPopovers(); state.wm.open('settings'); });
    $('btn-qs-lock').addEventListener('click', () => { closeShellPopovers(); requestSessionLock(); });
    $('btn-qs-panic').addEventListener('click', () => {
      closeShellPopovers();
      $('panic-arm-check').checked = false;
      $('panic-burn-vault').checked = false;
      $('btn-panic-confirm').disabled = true;
      $('panic-modal').hidden = false;
    });

    $('qs-tile-tor').addEventListener('click', async () => {
      try {
        await apiFetch('/api/tor/newnym', { method: 'POST', body: {} });
        pushToast('Tor SIGNAL NEWNYM dispatched.');
        pollSystemTelemetry();
      } catch (err) {
        pushToast(`NEWNYM failed: ${err.message}`, true);
      }
    });

    $('qs-tile-browser').addEventListener('click', () => {
      closeShellPopovers();
      if (state.appHooks.toggleBrowserFromQs) state.appHooks.toggleBrowserFromQs();
    });

    $('qs-tile-onionshare').addEventListener('click', () => {
      closeShellPopovers();
      state.wm.open('onionshare');
    });

    $('qs-tile-firewall').addEventListener('click', () => {
      closeShellPopovers();
      state.wm.open('settings');
    });

    $('qs-tile-relay').addEventListener('click', () => {
      closeShellPopovers();
      if (state.appHooks.toggleRelayFromQs) state.appHooks.toggleRelayFromQs();
    });

    document.querySelectorAll('#qs-popover .wallpaper-swatch').forEach((sw) => {
      sw.addEventListener('click', () => saveSystemSettings({ wallpaper: sw.dataset.wp }));
    });

    // Activities Search
    $('overview-search-input').addEventListener('input', () => renderActivitiesOverview());

    // Desktop Right-Click Context Menu
    const stage = $('workspace-stage');
    const ctxMenu = $('desktop-ctx-menu');
    stage.addEventListener('contextmenu', (e) => {
      if (e.target !== stage) return;
      e.preventDefault();
      closeShellPopovers();
      ctxMenu.style.left = `${Math.min(window.innerWidth - 230, e.clientX)}px`;
      ctxMenu.style.top = `${Math.min(window.innerHeight - 230, e.clientY)}px`;
      ctxMenu.hidden = false;
    });

    ctxMenu.querySelectorAll('[data-ctx-action]').forEach((item) => {
      item.addEventListener('click', () => {
        const act = item.dataset.ctxAction;
        ctxMenu.hidden = true;
        if (act === 'new-note') state.wm.open('editor', { root: 'ram', path: '/Documents/note.md' });
        else if (act === 'open-files') state.wm.open('files');
        else if (act === 'open-relay') state.wm.open('relay');
        else if (act === 'open-terminal') state.wm.open('terminal');
        else if (act === 'cycle-wallpaper') {
          const nextIdx = (WALLPAPERS.indexOf(state.settings.wallpaper) + 1) % WALLPAPERS.length;
          saveSystemSettings({ wallpaper: WALLPAPERS[nextIdx] });
        } else if (act === 'open-settings') state.wm.open('settings');
        else if (act === 'lock') requestSessionLock();
      });
    });

    document.addEventListener('pointerdown', (e) => {
      if (!ctxMenu.hidden && !ctxMenu.contains(e.target)) ctxMenu.hidden = true;
      if (
        !$('calendar-popover').hidden &&
        !$('calendar-popover').contains(e.target) &&
        !$('btn-top-clock').contains(e.target)
      ) {
        $('calendar-popover').hidden = true;
        $('btn-top-clock').classList.remove('is-active');
      }
      if (
        !$('qs-popover').hidden &&
        !$('qs-popover').contains(e.target) &&
        !$('btn-quick-settings').contains(e.target)
      ) {
        $('qs-popover').hidden = true;
        $('btn-quick-settings').classList.remove('is-active');
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        if (!$('panic-modal').hidden) $('panic-modal').hidden = true;
        else closeShellPopovers();
      }
    });

    // Guarded Panic Burn Modal
    $('panic-arm-check').addEventListener('change', (e) => {
      $('btn-panic-confirm').disabled = !e.target.checked;
    });
    $('btn-panic-cancel').addEventListener('click', () => { $('panic-modal').hidden = true; });
    $('btn-panic-confirm').addEventListener('click', async () => {
      const btn = $('btn-panic-confirm');
      btn.disabled = true;
      try {
        const r = await apiFetch('/api/system/panic-burn', {
          method: 'POST',
          body: { burnVault: Boolean($('panic-burn-vault').checked) },
        });
        lockDesktopUI(`PANIC BURN COMPLETE (${r.elapsedMs ?? 0}ms): ${r.burnedFiles ?? 0} RAM files shredded${r.vaultBurned ? ', persistent vault destroyed' : ''}.`);
      } catch (err) {
        pushToast(`Panic Burn error: ${err.message}`, true);
        btn.disabled = false;
      }
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    mountShellStaticIcons();

    state.wm = window.OnionWM.createManager({
      stageEl: $('workspace-stage'),
      snapPreviewEl: $('wm-snap-preview'),
      onStateChange: renderDockAndTopbar,
      onWindowResize: (appId) => {
        if (appId === 'terminal' && state.appHooks.resizeTerminal) {
          state.appHooks.resizeTerminal();
        }
      },
    });

    registerOnionTalkApp(state.wm);
    registerBrowserApp(state.wm);
    registerFilesApp(state.wm);
    registerOnionShareApp(state.wm);
    registerPasswordsApp(state.wm);
    registerEditorApp(state.wm);
    registerCleanerStudioApp(state.wm);
    registerNetworkLabApp(state.wm);
    registerConsoleApp(state.wm);
    registerSettingsApp(state.wm);
    registerRelayApp(state.wm);

    wireShellEvents();
    paintAllWallpaperCanvases();
    window.addEventListener('resize', () => window.requestAnimationFrame(paintAllWallpaperCanvases));
    updateClocks();
    state.timers.clock = window.setInterval(updateClocks, 10000);
    refreshGdmStatus();
  });
})();
