/* ================================================================
   MediFlow — Core App JS  (UUID-aware build)
   API client, auth, routing, layout, utilities
================================================================ */

const API_BASE = 'http://localhost:8000';

// ── Auth ─────────────────────────────────────────────────────
const Auth = {
  getToken()  { return localStorage.getItem('mf_token'); },
  getUser()   { try { return JSON.parse(localStorage.getItem('mf_user') || 'null'); } catch { return null; } },
  getRole()   { return this.getUser()?.role || null; },
  isLoggedIn(){ return !!this.getToken(); },
  save(data) {
    localStorage.setItem('mf_token', data.access_token);
    localStorage.setItem('mf_user', JSON.stringify({ id: data.user_id, username: data.username, role: data.role }));
  },
  clear() { localStorage.removeItem('mf_token'); localStorage.removeItem('mf_user'); },
};

// ── API Client ───────────────────────────────────────────────
const API = {
  async request(method, path, body = null, params = null) {
    let url = `${API_BASE}${path}`;
    if (params) {
      const qs = new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([,v]) => v != null && v !== '')));
      if (qs.toString()) url += '?' + qs;
    }
    const headers = { 'Content-Type': 'application/json' };
    const token = Auth.getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);
    try {
      const res = await fetch(url, opts);
      if (res.status === 401 && path !== '/api/auth/login') { Auth.clear(); Router.go('login'); return null; }
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || `Error ${res.status}`);
      return data;
    } catch(err) {
      Toast.error('Request Failed', err.message);
      throw err;
    }
  },
  get:    (path, params) => API.request('GET',    path, null, params),
  post:   (path, body)   => API.request('POST',   path, body),
  put:    (path, body)   => API.request('PUT',    path, body),
  patch:  (path, body)   => API.request('PATCH',  path, body),
  delete: (path)         => API.request('DELETE', path),

  // ── Auth endpoints
  login:    (u, p)   => API.post('/api/auth/login',    { username: u, password: p }),
  register: (d)      => API.post('/api/auth/register', d),
  logout:   ()       => API.post('/api/auth/logout'),
  me:       ()       => API.get('/api/auth/me'),

  // ── Patients
  patients:      (s=0, l=50)   => API.get('/api/patients/',    { skip: s, limit: l }),
  patient:       (id)           => API.get(`/api/patients/${id}`),
  createPatient: (d)            => API.post('/api/patients/', d),
  updatePatient: (id, d)        => API.put(`/api/patients/${id}`, d),
  deletePatient: (id)           => API.delete(`/api/patients/${id}`),

  // ── Doctors
  doctors:       (s=0, l=50)   => API.get('/api/doctors/', { skip: s, limit: l }),
  doctor:        (id)           => API.get(`/api/doctors/${id}`),
  createDoctor:  (d)            => API.post('/api/doctors/', d),
  updateDoctor:  (id, d)        => API.put(`/api/doctors/${id}`, d),
  deleteDoctor:  (id)           => API.delete(`/api/doctors/${id}`),

  // ── Appointments
  appointments:    (q)     => API.get('/api/appointments/',       q),
  appointment:     (id)    => API.get(`/api/appointments/${id}`),
  bookAppointment: (d)     => API.post('/api/appointments/', d),
  completeAppt:    (id, m) => API.patch(`/api/appointments/${id}/complete?duration_mins=${m}`),
  cancelAppt:      (id)    => API.patch(`/api/appointments/${id}/cancel`),

  // ── Queue
  liveQueue:         (dId, bId) => API.get(`/api/queue/live/${dId}/${bId}`),
  nextPatient:       (dId, bId) => API.get(`/api/queue/next/${dId}/${bId}`),
  queueStatus:       (qId, s)   => API.patch(`/api/queue/status/${qId}?new_status=${s}`),
  emergencyOverride: (d)         => API.post('/api/queue/emergency-override', d),
  recalculate:       (dId, bId) => API.post(`/api/queue/recalculate/${dId}/${bId}`),

  // ── Branches
  branches:       ()            => API.get('/api/branches/'),
  nearest:        (lat, lng, k) => API.get('/api/branches/nearest', { lat, lng, k }),
  loadSummary:    ()            => API.get('/api/branches/load-summary'),
  suggestRouting: (bId)         => API.get('/api/branches/suggest-routing', { origin_branch_id: bId }),
  createBranch:   (d)           => API.post('/api/branches/', d),

  // ── Analytics
  summary:        ()            => API.get('/api/analytics/summary'),
  peakForecast:   (bId, dId)   => API.get('/api/analytics/peak-forecast',    { branch_id: bId, department_id: dId }),
  waitTimeTrends: (dId, days)  => API.get('/api/analytics/wait-time-trends', { department_id: dId, days }),
  doctorPerf:     (dId, days)  => API.get('/api/analytics/doctor-performance',{ doctor_id: dId, days }),
  branchLoad:     (bId, hours) => API.get('/api/analytics/branch-load-history',{ branch_id: bId, hours }),
};

// ── Toast ─────────────────────────────────────────────────────
const Toast = {
  init() {
    if (!document.getElementById('toast-container')) {
      const c = document.createElement('div');
      c.id = 'toast-container'; c.className = 'toast-container';
      document.body.appendChild(c);
    }
  },
  show(type, title, sub = '', dur = 3500) {
    this.init();
    const icons = { success: '✓', error: '✕', info: 'ℹ', warning: '⚠' };
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.innerHTML = `<span class="toast-icon">${icons[type]||'ℹ'}</span><div><div class="toast-text">${title}</div>${sub ? `<div class="toast-sub">${sub}</div>` : ''}</div>`;
    document.getElementById('toast-container').appendChild(t);
    setTimeout(() => { t.style.cssText = 'opacity:0;transform:translateX(20px);transition:all .3s'; setTimeout(() => t.remove(), 300); }, dur);
  },
  success: (t, s) => Toast.show('success', t, s),
  error:   (t, s) => Toast.show('error',   t, s),
  info:    (t, s) => Toast.show('info',    t, s),
  warning: (t, s) => Toast.show('warning', t, s),
};

// ── Router ────────────────────────────────────────────────────
const Router = {
  go(page) {
    if (!Auth.isLoggedIn() && page !== 'login' && page !== 'signup') {
      this.render('login'); return;
    }
    this.render(page);
  },
  render(page) {
    document.title = `MediFlow — ${page.charAt(0).toUpperCase() + page.slice(1)}`;
    const app = document.getElementById('app');
    if (!app) return;
    if (page === 'login')  { app.innerHTML = Pages.loginPage();  Pages.initLogin();  return; }
    if (page === 'signup') { app.innerHTML = Pages.signupPage(); Pages.initSignup(); return; }
    app.innerHTML = Layout.shell(page);
    Layout.initNav(page);
    const content = document.getElementById('page-content');
    const map = {
      dashboard: Pages.renderDashboard, patients: Pages.renderPatients,
      doctors: Pages.renderDoctors, appointments: Pages.renderAppointments,
      queue: Pages.renderQueue, branches: Pages.renderBranches, analytics: Pages.renderAnalytics,
    };
    if (map[page]) map[page](content);
    else content.innerHTML = '<p style="color:var(--text-muted);padding:40px">Page not found.</p>';
  },
};

// ── Layout ────────────────────────────────────────────────────
const Layout = {
  shell(activePage) {
    const user = Auth.getUser();
    const initials = (user?.username || 'MF').slice(0, 2).toUpperCase();
    const navSections = {
      'Overview': [{ id: 'dashboard', icon: '⬡', label: 'Dashboard' }],
      'Clinical': [
        { id: 'patients',     icon: '♡', label: 'Patients'     },
        { id: 'doctors',      icon: '⚕', label: 'Physicians'   },
        { id: 'appointments', icon: '◷', label: 'Appointments' },
        { id: 'queue',        icon: '▤', label: 'Live Queue'   },
      ],
      'Operations': [
        { id: 'branches',  icon: '◈', label: 'Branches'  },
        { id: 'analytics', icon: '◉', label: 'Analytics' },
      ],
    };
    const navHtml = Object.entries(navSections).map(([sec, items]) => `
      <div class="nav-section">
        <div class="nav-section-label">${sec}</div>
        ${items.map(n => `
          <div class="nav-item ${n.id === activePage ? 'active' : ''}" data-page="${n.id}">
            <span class="nav-icon">${n.icon}</span><span>${n.label}</span>
          </div>`).join('')}
      </div>`).join('');
    return `
      <div class="app-shell">
        <header class="topbar">
          <div class="logo">
            <div class="logo-mark">✚</div>
            <span class="logo-text">Medi<span>Flow</span></span>
          </div>
          <div class="topbar-right">
            <div class="topbar-badge" id="api-status">● Connecting…</div>
            <div class="user-chip" onclick="Modal.showUserMenu()">
              <div class="avatar">${initials}</div>
              <span style="font-size:.85rem;color:var(--text-secondary)">${user?.username||'User'}</span>
              <span style="font-size:.72rem;color:var(--text-muted);margin-left:4px;font-family:var(--font-mono)">${user?.role||''}</span>
            </div>
          </div>
        </header>
        <nav class="sidebar">
          ${navHtml}
          <div class="sidebar-footer">
            <div class="nav-item" id="logout-btn">
              <span class="nav-icon">⏻</span><span>Sign Out</span>
            </div>
          </div>
        </nav>
        <main class="main-content" id="page-content">
          <div style="text-align:center;padding:80px;color:var(--text-muted)">Loading…</div>
        </main>
      </div>`;
  },

  initNav(activePage) {
    document.querySelectorAll('.nav-item[data-page]').forEach(el =>
      el.addEventListener('click', () => Router.go(el.dataset.page)));
    document.getElementById('logout-btn')?.addEventListener('click', async () => {
      try { await API.logout(); } catch(e) {}
      Auth.clear(); Toast.info('Signed out', 'See you soon.');
      setTimeout(() => Router.go('login'), 500);
    });
    fetch(`${API_BASE}/health`).then(r => {
      const b = document.getElementById('api-status');
      if (!b) return;
      if (r.ok) { b.textContent = '● API Live'; b.style.cssText = 'color:var(--green);border-color:var(--green);background:var(--green-dim)'; }
      else      { b.textContent = '● API Error'; b.style.cssText = 'color:var(--red);border-color:var(--red);background:var(--red-dim)'; }
    }).catch(() => {
      const b = document.getElementById('api-status');
      if (b) { b.textContent = '● Offline'; b.style.cssText = 'color:var(--text-muted);border-color:var(--border);background:transparent'; }
    });
  },
};

// ── Modal ─────────────────────────────────────────────────────
const Modal = {
  open(id)  { document.getElementById(id)?.classList.add('open'); },
  close(id) { document.getElementById(id)?.classList.remove('open'); },
  create(id, title, body, footer = '') {
    document.getElementById(id)?.remove();
    const el = document.createElement('div');
    el.id = id; el.className = 'modal-overlay';
    el.innerHTML = `
      <div class="modal">
        <div class="modal-header">
          <h3 class="modal-title">${title}</h3>
          <button class="btn-close" onclick="Modal.close('${id}')">✕</button>
        </div>
        <div class="modal-body">${body}</div>
        ${footer ? `<div class="modal-footer">${footer}</div>` : ''}
      </div>`;
    el.addEventListener('click', e => { if (e.target === el) Modal.close(id); });
    document.body.appendChild(el);
    setTimeout(() => el.classList.add('open'), 10);
  },
  showUserMenu() {
    const u = Auth.getUser();
    Modal.create('user-modal', 'Account', `
      <div class="metric-row"><span class="metric-label">Username</span><span class="metric-value">${u?.username}</span></div>
      <div class="metric-row"><span class="metric-label">Role</span><span class="metric-value">${u?.role}</span></div>
      <div class="metric-row"><span class="metric-label">User ID</span><span class="metric-value mono" style="font-size:.72rem">${u?.id}</span></div>`,
    `<button class="btn btn-danger btn-sm" onclick="document.getElementById('logout-btn').click();Modal.close('user-modal')">Sign Out</button>
     <button class="btn btn-secondary btn-sm" onclick="Modal.close('user-modal')">Close</button>`);
  },
};

// ── Helpers ───────────────────────────────────────────────────
const Fmt = {
  date(d)    { return d ? new Date(d).toLocaleDateString('en-US', {year:'numeric',month:'short',day:'numeric'}) : '—'; },
  datetime(d){ if (!d) return '—'; const dt = new Date(d); return dt.toLocaleDateString('en-US',{month:'short',day:'numeric'}) + ' ' + dt.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'}); },
  badge(val) {
    const cls = `badge-${(val||'').toLowerCase().replace(/\s+/g,'_')}`;
    return `<span class="badge ${cls}">${val||'—'}</span>`;
  },
  initials(name) { return (name||'?').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase(); },
  yesno(v)   { return v ? '<span style="color:var(--green)">●</span>' : '<span style="color:var(--text-muted)">○</span>'; },
  shortId(uuid) { return uuid ? uuid.slice(0,8) + '…' : '—'; },
};

const $ = (s, ctx=document) => ctx.querySelector(s);
const $$ = (s, ctx=document) => [...ctx.querySelectorAll(s)];
const spinner = () => `<div style="text-align:center;padding:60px;color:var(--text-muted);font-family:var(--font-mono);font-size:.85rem"><span class="loading-dot"></span> Loading…</div>`;
const noData  = (msg='No data') => `<div class="empty-state"><div class="empty-state-icon">◌</div><div class="empty-state-text">${msg}</div></div>`;
