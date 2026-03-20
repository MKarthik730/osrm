/* ================================================================
   MediFlow — Pages JS  (UUID-aware + Signup)
================================================================ */

const Pages = {

  // ════════════════════════════════════════════════════════════
  // LOGIN
  // ════════════════════════════════════════════════════════════
  loginPage() {
    return `
      <div class="login-page">
        <div class="login-bg"></div>
        <div class="login-grid-lines"></div>
        <div class="login-box animate-in">
          <div class="login-logo">
            <div class="login-logo-mark">✚</div>
            <div class="login-logo-text">Medi<b>Flow</b></div>
          </div>
          <div class="login-tagline">Intelligent Healthcare Scheduling Platform</div>
          <div class="login-error" id="login-error"></div>
          <div class="form-group">
            <label>Username</label>
            <input type="text" id="login-user" placeholder="Enter your username" autocomplete="username">
          </div>
          <div class="form-group">
            <label>Password</label>
            <input type="password" id="login-pass" placeholder="Enter your password" autocomplete="current-password">
          </div>
          <button class="btn btn-primary" id="login-btn" style="width:100%;justify-content:center;margin-top:4px">
            Sign In →
          </button>
          <div style="text-align:center;margin-top:20px;font-size:.8rem;color:var(--text-muted)">
            Don't have an account?
            <a href="#" onclick="Router.go('signup')" style="color:var(--gold);margin-left:4px">Create account</a>
          </div>
          <div style="text-align:center;margin-top:20px;font-size:.7rem;color:var(--text-muted);font-family:var(--font-mono)">
            MediFlow v1.0 &nbsp;·&nbsp; Priority Queue Scheduling
          </div>
        </div>
      </div>`;
  },

  initLogin() {
    const go = async () => {
      const u = $('#login-user').value.trim();
      const p = $('#login-pass').value;
      const btn = $('#login-btn'), err = $('#login-error');
      if (!u || !p) { err.textContent = 'Username and password are required.'; err.classList.add('show'); return; }
      btn.textContent = 'Signing in…'; btn.disabled = true; err.classList.remove('show');
      try {
        const data = await API.login(u, p);
        if (!data) { btn.textContent = 'Sign In →'; btn.disabled = false; return; }
        Auth.save(data);
        Toast.success('Welcome back', data.username);
        Router.go('dashboard');
      } catch(e) {
        err.textContent = e.message || 'Invalid credentials';
        err.classList.add('show');
        btn.textContent = 'Sign In →'; btn.disabled = false;
      }
    };
    $('#login-btn')?.addEventListener('click', go);
    $('#login-pass')?.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
    setTimeout(() => $('#login-user')?.focus(), 100);
  },

  // ════════════════════════════════════════════════════════════
  // SIGNUP
  // ════════════════════════════════════════════════════════════
  signupPage() {
    return `
      <div class="login-page">
        <div class="login-bg"></div>
        <div class="login-grid-lines"></div>
        <div class="login-box animate-in" style="max-width:480px">
          <div class="login-logo">
            <div class="login-logo-mark">✚</div>
            <div class="login-logo-text">Medi<b>Flow</b></div>
          </div>
          <div class="login-tagline">Create Your Account</div>
          <div class="login-error" id="signup-error"></div>
          <div class="form-grid" style="grid-template-columns:1fr 1fr;gap:16px">
            <div class="form-group">
              <label>Username *</label>
              <input type="text" id="su-username" placeholder="john_doe" autocomplete="username">
            </div>
            <div class="form-group">
              <label>Role *</label>
              <select id="su-role">
                <option value="patient">Patient</option>
                <option value="doctor">Doctor</option>
                <option value="staff">Staff</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          </div>
          <div class="form-group">
            <label>Password *</label>
            <input type="password" id="su-pass" placeholder="At least 8 characters" autocomplete="new-password">
          </div>
          <div class="form-group">
            <label>Confirm Password *</label>
            <input type="password" id="su-pass2" placeholder="Repeat password" autocomplete="new-password">
          </div>
          <div class="form-group" id="su-ref-group">
            <label>Reference Profile ID <span style="color:var(--text-muted);font-size:.7rem">(optional — link to patient/doctor/staff record)</span></label>
            <input type="text" id="su-ref-id" placeholder="UUID of your profile, or leave blank">
          </div>
          <div style="background:var(--bg-elevated);border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;margin-bottom:20px;font-size:.8rem;color:var(--text-muted)">
            <strong style="color:var(--gold)">Note:</strong> After creating your account, ask an administrator to link your profile if needed. You can sign in immediately.
          </div>
          <button class="btn btn-primary" id="signup-btn" style="width:100%;justify-content:center">
            Create Account →
          </button>
          <div style="text-align:center;margin-top:20px;font-size:.8rem;color:var(--text-muted)">
            Already have an account?
            <a href="#" onclick="Router.go('login')" style="color:var(--gold);margin-left:4px">Sign in</a>
          </div>
        </div>
      </div>`;
  },

  initSignup() {
    const go = async () => {
      const username = $('#su-username').value.trim();
      const role     = $('#su-role').value;
      const pass     = $('#su-pass').value;
      const pass2    = $('#su-pass2').value;
      const refId    = $('#su-ref-id').value.trim();
      const btn      = $('#signup-btn'), err = $('#signup-error');

      err.classList.remove('show');
      if (!username || !pass) { err.textContent = 'Username and password are required.'; err.classList.add('show'); return; }
      if (pass.length < 8)    { err.textContent = 'Password must be at least 8 characters.'; err.classList.add('show'); return; }
      if (pass !== pass2)     { err.textContent = 'Passwords do not match.'; err.classList.add('show'); return; }

      btn.textContent = 'Creating account…'; btn.disabled = true;
      try {
        const data = await API.register({
          username,
          role,
          password: pass,
          user_ref_id: refId || '00000000-0000-0000-0000-000000000000',
        });
        if (!data) { btn.textContent = 'Create Account →'; btn.disabled = false; return; }
        Toast.success('Account created!', `Welcome, ${username}. Please sign in.`);
        setTimeout(() => Router.go('login'), 1200);
      } catch(e) {
        err.textContent = e.message || 'Registration failed';
        err.classList.add('show');
        btn.textContent = 'Create Account →'; btn.disabled = false;
      }
    };
    $('#signup-btn')?.addEventListener('click', go);
    $('#su-pass2')?.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
    setTimeout(() => $('#su-username')?.focus(), 100);
  },

  // ════════════════════════════════════════════════════════════
  // DASHBOARD
  // ════════════════════════════════════════════════════════════
  async renderDashboard(el) {
    el.innerHTML = `
      <div class="page-header animate-in">
        <div>
          <h2 class="page-title">Dashboard</h2>
          <div class="page-subtitle">${new Date().toDateString()} — Operational Overview</div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="Pages.renderDashboard(document.getElementById('page-content'))">↻ Refresh</button>
      </div>
      <div class="stat-grid" id="dash-stats">
        ${[0,1,2,3].map(()=>`<div class="stat-card">${spinner()}</div>`).join('')}
      </div>
      <div class="two-col">
        <div class="card animate-in">
          <div class="card-header"><span class="card-title">Recent Appointments</span>
            <button class="btn btn-ghost btn-sm" onclick="Router.go('appointments')">View all →</button>
          </div>
          <div class="card-body" id="dash-appts">${spinner()}</div>
        </div>
        <div class="card animate-in">
          <div class="card-header"><span class="card-title">Branch Load</span>
            <button class="btn btn-ghost btn-sm" onclick="Router.go('branches')">Manage →</button>
          </div>
          <div class="card-body" id="dash-load">${spinner()}</div>
        </div>
      </div>`;
    try {
      const s = await API.summary();
      if (s) document.getElementById('dash-stats').innerHTML = `
        <div class="stat-card" style="--accent:var(--gold)">
          <div class="stat-icon" style="background:var(--gold-dim);color:var(--gold)">◷</div>
          <div class="stat-value">${s.appointments_today}</div><div class="stat-label">Today</div></div>
        <div class="stat-card" style="--accent:var(--green)">
          <div class="stat-icon" style="background:var(--green-dim);color:var(--green)">✓</div>
          <div class="stat-value">${s.total_completed}</div><div class="stat-label">Completed</div></div>
        <div class="stat-card" style="--accent:var(--red)">
          <div class="stat-icon" style="background:var(--red-dim);color:var(--red)">✕</div>
          <div class="stat-value">${s.total_cancelled}</div><div class="stat-label">Cancelled</div></div>
        <div class="stat-card" style="--accent:var(--red)">
          <div class="stat-icon" style="background:var(--red-dim);color:var(--red)">⚠</div>
          <div class="stat-value">${s.critical_cases}</div><div class="stat-label">Critical</div></div>`;
    } catch(e) {}
    try {
      const appts = await API.appointments({ limit: 6 });
      const el2 = document.getElementById('dash-appts');
      if (!appts?.length) { el2.innerHTML = noData('No appointments yet'); return; }
      el2.innerHTML = `<div class="table-wrapper"><table><thead><tr><th>ID</th><th>Type</th><th>Status</th><th>Urgency</th><th>Scheduled</th></tr></thead><tbody>
        ${appts.map(a => `<tr>
          <td class="mono" style="font-size:.72rem;color:var(--text-muted)">${Fmt.shortId(a.appointment_id)}</td>
          <td style="text-transform:capitalize">${a.appointment_type}</td>
          <td>${Fmt.badge(a.status)}</td><td>${Fmt.badge(a.urgency_level)}</td>
          <td style="font-size:.78rem">${Fmt.datetime(a.scheduled_time)}</td>
        </tr>`).join('')}
        </tbody></table></div>`;
    } catch(e) { document.getElementById('dash-appts').innerHTML = noData('Could not load appointments'); }
    try {
      const loads = await API.loadSummary();
      const el3 = document.getElementById('dash-load');
      if (!loads?.length) { el3.innerHTML = noData('No branches configured'); return; }
      el3.innerHTML = loads.map(b => {
        const pct = b.total_capacity > 0 ? Math.round((b.current_load / b.total_capacity) * 100) : 0;
        const color = b.is_overloaded ? 'var(--red)' : pct > 60 ? 'var(--amber)' : 'var(--green)';
        return `<div class="load-bar-row">
          <div class="load-bar-label" style="font-size:.78rem">Branch ${Fmt.shortId(String(b.branch_id))}</div>
          <div class="load-bar-track"><div class="load-bar-fill" style="width:${pct}%;background:${color}"></div></div>
          <div class="load-bar-pct">${pct}%</div>
        </div>`;
      }).join('');
    } catch(e) { document.getElementById('dash-load').innerHTML = noData('Could not load branch data'); }
  },

  // ════════════════════════════════════════════════════════════
  // PATIENTS
  // ════════════════════════════════════════════════════════════
  async renderPatients(el) {
    el.innerHTML = `
      <div class="page-header animate-in">
        <div><h2 class="page-title">Patients</h2><div class="page-subtitle">Patient records management</div></div>
        <div style="display:flex;gap:10px;align-items:center">
          <div class="search-bar" style="width:200px">
            <span class="search-icon">⌕</span>
            <input type="text" id="pt-search" placeholder="Filter…">
          </div>
          <button class="btn btn-primary" onclick="Pages.openPatientModal()">+ Add Patient</button>
        </div>
      </div>
      <div class="card animate-in">
        <div class="card-body" id="patients-table">${spinner()}</div>
      </div>`;
    Pages.loadPatientsTable();
    document.getElementById('pt-search')?.addEventListener('input', e => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('#patients-table tbody tr').forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  },

  async loadPatientsTable() {
    const el = document.getElementById('patients-table');
    if (!el) return;
    try {
      const pts = await API.patients();
      if (!pts?.length) { el.innerHTML = noData('No patients found'); return; }
      el.innerHTML = `<div class="table-wrapper"><table><thead><tr>
        <th>ID</th><th>Name</th><th>DOB</th><th>Gender</th><th>Blood</th><th>Phone</th><th>Email</th><th>Status</th><th></th>
      </tr></thead><tbody>
        ${pts.map(p => `<tr>
          <td class="mono" style="font-size:.68rem;color:var(--text-muted)">${Fmt.shortId(p.patient_id)}</td>
          <td><div style="display:flex;align-items:center;gap:10px">
            <div class="avatar" style="width:28px;height:28px;font-size:.65rem;border-radius:7px;flex-shrink:0">${Fmt.initials(p.full_name)}</div>
            <span style="color:var(--text-primary);font-weight:500">${p.full_name}</span></div></td>
          <td style="font-size:.8rem">${Fmt.date(p.date_of_birth)}</td>
          <td style="text-transform:capitalize;font-size:.82rem">${p.gender||'—'}</td>
          <td><span class="badge badge-medium">${p.blood_group||'—'}</span></td>
          <td class="mono" style="font-size:.78rem">${p.phone||'—'}</td>
          <td style="font-size:.78rem">${p.email||'—'}</td>
          <td>${Fmt.yesno(p.is_active)} <span style="font-size:.72rem;color:var(--text-muted)">${p.is_active?'Active':'Inactive'}</span></td>
          <td><div style="display:flex;gap:5px">
            <button class="btn btn-secondary btn-sm" onclick="Pages.openPatientModal('${p.patient_id}')">Edit</button>
            <button class="btn btn-danger btn-sm" onclick="Pages.deletePatient('${p.patient_id}','${p.full_name}')">✕</button>
          </div></td>
        </tr>`).join('')}
      </tbody></table></div>`;
    } catch(e) { el.innerHTML = noData('Failed to load patients'); }
  },

  async openPatientModal(id = null) {
    let p = null;
    if (id) { try { p = await API.patient(id); } catch(e) {} }
    Modal.create('patient-modal', id ? `Edit Patient` : 'New Patient', `
      <div class="form-grid">
        <div class="form-group"><label>Full Name *</label><input type="text" id="p-name" value="${p?.full_name||''}" placeholder="Jane Doe"></div>
        <div class="form-group"><label>Date of Birth</label><input type="date" id="p-dob" value="${p?.date_of_birth||''}"></div>
        <div class="form-group"><label>Gender</label>
          <select id="p-gender">${['','Male','Female','Other','Prefer not to say'].map(g=>`<option value="${g}" ${p?.gender===g?'selected':''}>${g||'Select…'}</option>`).join('')}</select></div>
        <div class="form-group"><label>Blood Group</label>
          <select id="p-blood">${['','A+','A-','B+','B-','AB+','AB-','O+','O-'].map(g=>`<option value="${g}" ${p?.blood_group===g?'selected':''}>${g||'Select…'}</option>`).join('')}</select></div>
        <div class="form-group"><label>Phone</label><input type="tel" id="p-phone" value="${p?.phone||''}" placeholder="+1 555 000 0000"></div>
        <div class="form-group"><label>Email</label><input type="email" id="p-email" value="${p?.email||''}" placeholder="patient@email.com"></div>
      </div>
      <div class="form-group"><label>Address</label><textarea id="p-addr" rows="2">${p?.address||''}</textarea></div>`,
    `<button class="btn btn-secondary" onclick="Modal.close('patient-modal')">Cancel</button>
     <button class="btn btn-primary" onclick="Pages.savePatient('${id||''}')">
       ${id ? 'Save Changes' : 'Create Patient'}</button>`);
  },

  async savePatient(id) {
    const data = { full_name: $('#p-name').value.trim(), date_of_birth: $('#p-dob').value||null,
      gender: $('#p-gender').value||null, blood_group: $('#p-blood').value||null,
      phone: $('#p-phone').value||null, email: $('#p-email').value||null, address: $('#p-addr').value||null };
    if (!data.full_name) { Toast.error('Validation', 'Full name is required'); return; }
    try {
      if (id) await API.updatePatient(id, data); else await API.createPatient(data);
      Toast.success(id ? 'Patient updated' : 'Patient created', data.full_name);
      Modal.close('patient-modal'); Pages.loadPatientsTable();
    } catch(e) {}
  },

  async deletePatient(id, name) {
    if (!confirm(`Deactivate patient "${name}"?`)) return;
    try { await API.deletePatient(id); Toast.success('Deactivated', name); Pages.loadPatientsTable(); } catch(e) {}
  },

  // ════════════════════════════════════════════════════════════
  // DOCTORS
  // ════════════════════════════════════════════════════════════
  async renderDoctors(el) {
    el.innerHTML = `
      <div class="page-header animate-in">
        <div><h2 class="page-title">Physicians</h2><div class="page-subtitle">Clinical staff directory</div></div>
        <button class="btn btn-primary" onclick="Pages.openDoctorModal()">+ Add Physician</button>
      </div>
      <div id="doctors-grid" class="three-col animate-in">${spinner()}</div>`;
    Pages.loadDoctors();
  },

  async loadDoctors() {
    const el = document.getElementById('doctors-grid');
    if (!el) return;
    try {
      const docs = await API.doctors();
      if (!docs?.length) { el.innerHTML = noData('No physicians found'); return; }
      el.innerHTML = docs.map(d => `
        <div class="doctor-card">
          <div style="display:flex;align-items:center;gap:12px">
            <div class="doctor-avatar">${Fmt.initials(d.full_name)}</div>
            <div><div class="doctor-name">Dr. ${d.full_name}</div>
              <div class="doctor-spec">${d.specialization||'General Practice'}</div></div>
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap">
            ${d.is_active ? '<span class="badge badge-completed">Active</span>' : '<span class="badge badge-cancelled">Inactive</span>'}
            ${d.experience_yrs ? `<span class="badge badge-scheduled">${d.experience_yrs}yr exp</span>` : ''}
          </div>
          <div class="metric-row" style="padding:5px 0">
            <span class="metric-label" style="font-size:.75rem">Avg Consult</span>
            <span class="metric-value" style="font-size:.82rem">${d.avg_consult_mins||15} min</span>
          </div>
          ${d.qualification ? `<div style="font-size:.75rem;color:var(--text-muted)">${d.qualification}</div>` : ''}
          <div style="display:flex;gap:8px;margin-top:4px">
            <button class="btn btn-secondary btn-sm" style="flex:1" onclick="Pages.openDoctorModal('${d.doctor_id}')">Edit</button>
            <button class="btn btn-danger btn-sm" onclick="Pages.deleteDoctor('${d.doctor_id}','${d.full_name}')">✕</button>
          </div>
        </div>`).join('');
    } catch(e) { el.innerHTML = noData('Failed to load physicians'); }
  },

  async openDoctorModal(id = null) {
    let d = null;
    if (id) { try { d = await API.doctor(id); } catch(e) {} }
    Modal.create('doctor-modal', id ? 'Edit Physician' : 'New Physician', `
      <div class="form-grid">
        <div class="form-group"><label>Full Name *</label><input type="text" id="d-name" value="${d?.full_name||''}" placeholder="Dr. John Smith"></div>
        <div class="form-group"><label>Specialization</label><input type="text" id="d-spec" value="${d?.specialization||''}" placeholder="Cardiology"></div>
        <div class="form-group"><label>Qualification</label><input type="text" id="d-qual" value="${d?.qualification||''}" placeholder="MBBS, MD"></div>
        <div class="form-group"><label>Experience (years)</label><input type="number" id="d-exp" value="${d?.experience_yrs||''}" placeholder="5"></div>
        <div class="form-group"><label>Avg Consult (min)</label><input type="number" id="d-time" value="${d?.avg_consult_mins||15}" placeholder="15"></div>
        <div class="form-group"><label>Email</label><input type="email" id="d-email" value="${d?.email||''}" placeholder="dr@hospital.com"></div>
        <div class="form-group"><label>Phone</label><input type="tel" id="d-phone" value="${d?.phone||''}" placeholder="+1 555 000 0000"></div>
        <div class="form-group"><label>Department UUID</label><input type="text" id="d-dept" value="${d?.department_id||''}" placeholder="optional"></div>
      </div>`,
    `<button class="btn btn-secondary" onclick="Modal.close('doctor-modal')">Cancel</button>
     <button class="btn btn-primary" onclick="Pages.saveDoctor('${id||''}')">
       ${id ? 'Save Changes' : 'Create Physician'}</button>`);
  },

  async saveDoctor(id) {
    const data = { full_name: $('#d-name').value.trim(), specialization: $('#d-spec').value||null,
      qualification: $('#d-qual').value||null, experience_yrs: parseInt($('#d-exp').value)||null,
      avg_consult_mins: parseFloat($('#d-time').value)||15,
      email: $('#d-email').value||null, phone: $('#d-phone').value||null,
      department_id: $('#d-dept').value||null };
    if (!data.full_name) { Toast.error('Validation', 'Name is required'); return; }
    try {
      if (id) await API.updateDoctor(id, data); else await API.createDoctor(data);
      Toast.success(id ? 'Physician updated' : 'Physician created', data.full_name);
      Modal.close('doctor-modal'); Pages.loadDoctors();
    } catch(e) {}
  },

  async deleteDoctor(id, name) {
    if (!confirm(`Deactivate Dr. "${name}"?`)) return;
    try { await API.deleteDoctor(id); Toast.success('Deactivated', 'Dr. ' + name); Pages.loadDoctors(); } catch(e) {}
  },

  // ════════════════════════════════════════════════════════════
  // APPOINTMENTS
  // ════════════════════════════════════════════════════════════
  async renderAppointments(el) {
    el.innerHTML = `
      <div class="page-header animate-in">
        <div><h2 class="page-title">Appointments</h2><div class="page-subtitle">Scheduling & booking management</div></div>
        <button class="btn btn-primary" onclick="Pages.openBookModal()">+ Book Appointment</button>
      </div>
      <div class="tabs" id="appt-tabs">
        ${['All','scheduled','in_progress','completed','cancelled'].map((s,i) =>
          `<div class="tab ${i===0?'active':''}" data-filter="${i===0?'':s}">${i===0?'All':s.replace('_',' ').replace(/\b\w/g,l=>l.toUpperCase())}</div>`).join('')}
      </div>
      <div class="card animate-in"><div class="card-body" id="appts-table">${spinner()}</div></div>`;
    $$('.tab', document.getElementById('appt-tabs')).forEach(tab =>
      tab.addEventListener('click', () => {
        $$('.tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        Pages.loadAppointments(tab.dataset.filter||null);
      }));
    Pages.loadAppointments();
  },

  async loadAppointments(status = null) {
    const el = document.getElementById('appts-table');
    if (!el) return;
    el.innerHTML = spinner();
    try {
      let appts = await API.appointments({ limit: 100 }) || [];
      if (status) appts = appts.filter(a => a.status === status);
      if (!appts.length) { el.innerHTML = noData('No appointments found'); return; }
      el.innerHTML = `<div class="table-wrapper"><table><thead><tr>
        <th>ID</th><th>Patient</th><th>Doctor</th><th>Type</th><th>Urgency</th><th>Status</th><th>Scheduled</th><th>Actions</th>
      </tr></thead><tbody>
        ${appts.map(a => `<tr>
          <td class="mono" style="font-size:.68rem;color:var(--text-muted)">${Fmt.shortId(a.appointment_id)}</td>
          <td style="font-size:.78rem;color:var(--text-secondary)">${Fmt.shortId(a.patient_id)}</td>
          <td style="font-size:.78rem;color:var(--text-secondary)">${Fmt.shortId(a.doctor_id)}</td>
          <td><span class="badge badge-scheduled" style="text-transform:capitalize">${a.appointment_type}</span></td>
          <td>${Fmt.badge(a.urgency_level)}</td>
          <td>${Fmt.badge(a.status)}</td>
          <td style="font-size:.75rem">${Fmt.datetime(a.scheduled_time)}</td>
          <td><div style="display:flex;gap:5px">
            ${(a.status==='scheduled'||a.status==='in_progress') ? `
              <button class="btn btn-secondary btn-sm" onclick="Pages.completeAppt('${a.appointment_id}')">✓</button>
              <button class="btn btn-danger btn-sm" onclick="Pages.cancelAppt('${a.appointment_id}')">✕</button>` : ''}
          </div></td>
        </tr>`).join('')}
      </tbody></table></div>`;
    } catch(e) { el.innerHTML = noData('Failed to load appointments'); }
  },

  async openBookModal() {
    // Get available doctors and branches first
    let doctorOpts = '<option value="">Enter UUID manually below</option>';
    let branchOpts = '<option value="">Enter UUID manually below</option>';
    try {
      const docs = await API.doctors();
      if (docs?.length) doctorOpts = docs.map(d => `<option value="${d.doctor_id}">Dr. ${d.full_name} — ${d.specialization||'General'}</option>`).join('');
    } catch(e) {}
    try {
      const brs = await API.branches();
      if (brs?.length) branchOpts = brs.map(b => `<option value="${b.branch_id}">${b.branch_name} — ${b.city||''}</option>`).join('');
    } catch(e) {}

    Modal.create('book-modal', 'Book Appointment', `
      <div class="form-grid">
        <div class="form-group" style="grid-column:1/-1">
          <label>Patient UUID *</label>
          <input type="text" id="ap-patient" placeholder="Patient UUID (from Patients page)">
        </div>
        <div class="form-group">
          <label>Doctor *</label>
          <select id="ap-doctor-sel">${doctorOpts}</select>
        </div>
        <div class="form-group">
          <label>Branch *</label>
          <select id="ap-branch-sel">${branchOpts}</select>
        </div>
        <div class="form-group">
          <label>Urgency Level</label>
          <select id="ap-urgency">
            <option value="low">Low</option><option value="medium" selected>Medium</option>
            <option value="high">High</option><option value="critical">Critical</option>
          </select>
        </div>
        <div class="form-group">
          <label>Appointment Type</label>
          <select id="ap-type">
            <option value="consultation" selected>Consultation</option>
            <option value="surgery">Surgery</option>
            <option value="follow_up">Follow-up</option>
            <option value="emergency">Emergency</option>
          </select>
        </div>
        <div class="form-group" style="grid-column:1/-1">
          <label>Scheduled Time *</label>
          <input type="datetime-local" id="ap-time" value="${new Date().toISOString().slice(0,16)}">
        </div>
      </div>
      <div class="form-group"><label>Notes</label><textarea id="ap-notes" placeholder="Clinical notes…"></textarea></div>`,
    `<button class="btn btn-secondary" onclick="Modal.close('book-modal')">Cancel</button>
     <button class="btn btn-primary" onclick="Pages.saveAppointment()">Book Appointment</button>`);
  },

  async saveAppointment() {
    const data = {
      patient_id:       $('#ap-patient').value.trim(),
      doctor_id:        $('#ap-doctor-sel').value,
      branch_id:        $('#ap-branch-sel').value,
      urgency_level:    $('#ap-urgency').value,
      appointment_type: $('#ap-type').value,
      scheduled_time:   $('#ap-time').value||null,
      notes:            $('#ap-notes').value||null,
    };
    if (!data.patient_id || !data.doctor_id || !data.branch_id)
      { Toast.error('Validation', 'Patient, Doctor, and Branch are required'); return; }
    try {
      await API.bookAppointment(data);
      Toast.success('Appointment booked', `${data.appointment_type} — ${data.urgency_level} urgency`);
      Modal.close('book-modal'); Pages.loadAppointments();
    } catch(e) {}
  },

  async completeAppt(id) {
    const dur = prompt('Consultation duration (minutes):');
    if (!dur) return;
    try { await API.completeAppt(id, parseFloat(dur)); Toast.success('Completed', `${dur} min`); Pages.loadAppointments(); } catch(e) {}
  },

  async cancelAppt(id) {
    if (!confirm('Cancel this appointment?')) return;
    try { await API.cancelAppt(id); Toast.warning('Appointment cancelled', Fmt.shortId(id)); Pages.loadAppointments(); } catch(e) {}
  },

  // ════════════════════════════════════════════════════════════
  // QUEUE
  // ════════════════════════════════════════════════════════════
  async renderQueue(el) {
    // Pre-load doctors and branches for dropdowns
    let doctorOpts = '<option value="">Select doctor…</option>';
    let branchOpts = '<option value="">Select branch…</option>';
    try { const docs = await API.doctors(); doctorOpts = docs?.map(d => `<option value="${d.doctor_id}">Dr. ${d.full_name}</option>`).join('') || doctorOpts; } catch(e) {}
    try { const brs  = await API.branches(); branchOpts = brs?.map(b => `<option value="${b.branch_id}">${b.branch_name}</option>`).join('') || branchOpts; } catch(e) {}

    el.innerHTML = `
      <div class="page-header animate-in">
        <div><h2 class="page-title">Live Queue</h2><div class="page-subtitle">Real-time priority queue — Max-Heap · Little's Law</div></div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-danger btn-sm" onclick="Pages.openEmergencyModal()">⚠ Emergency Override</button>
          <button class="btn btn-secondary btn-sm" onclick="Pages.loadQueue()">↻ Refresh</button>
        </div>
      </div>
      <div class="card animate-in" style="margin-bottom:20px">
        <div class="card-body">
          <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
            <div class="form-group" style="margin:0;flex:1;min-width:180px">
              <label>Doctor</label>
              <select id="q-doctor-id">${doctorOpts}</select>
            </div>
            <div class="form-group" style="margin:0;flex:1;min-width:180px">
              <label>Branch</label>
              <select id="q-branch-id">${branchOpts}</select>
            </div>
            <button class="btn btn-primary" onclick="Pages.loadQueue()">Load Queue</button>
            <button class="btn btn-secondary" onclick="Pages.nextPatient()">Call Next →</button>
          </div>
        </div>
      </div>
      <div class="two-col">
        <div class="card animate-in">
          <div class="card-header">
            <span class="card-title">Queue</span>
            <span class="badge badge-waiting" id="q-count">0 waiting</span>
          </div>
          <div class="card-body" id="queue-list">${noData('Select doctor & branch above, then click Load Queue')}</div>
        </div>
        <div class="card animate-in">
          <div class="card-header"><span class="card-title">Algorithm Info</span></div>
          <div class="card-body">
            <div class="metric-row"><span class="metric-label">Data Structure</span><span class="metric-value">Max-Heap (inverted min-heap)</span></div>
            <div class="metric-row"><span class="metric-label">Insert/Extract</span><span class="metric-value mono">O(log n)</span></div>
            <div class="metric-row"><span class="metric-label">Score Formula</span><span class="metric-value" style="font-size:.75rem">Urgency×0.5 + Wait×0.3 + Age×0.1 + Type×0.1</span></div>
            <div class="metric-row"><span class="metric-label">Wait Estimation</span><span class="metric-value">Little's Law (L = λW)</span></div>
            <div class="metric-row"><span class="metric-label">Emergency Score</span><span class="metric-value mono" style="color:var(--red)">999 (preemptive)</span></div>
            <div class="metric-row"><span class="metric-label">Anti-Starvation</span><span class="metric-value">Wait score grows over time</span></div>
          </div>
        </div>
      </div>`;
  },

  async loadQueue() {
    const docId    = $('#q-doctor-id')?.value;
    const branchId = $('#q-branch-id')?.value;
    const listEl   = document.getElementById('queue-list');
    const countEl  = document.getElementById('q-count');
    if (!listEl || !docId || !branchId) {
      if (listEl) listEl.innerHTML = noData('Select doctor & branch first');
      return;
    }
    listEl.innerHTML = spinner();
    try {
      const queue = await API.liveQueue(docId, branchId);
      if (countEl) countEl.textContent = `${queue?.length||0} waiting`;
      if (!queue?.length) { listEl.innerHTML = noData('Queue is empty'); return; }
      listEl.innerHTML = `<div class="queue-list">
        ${queue.map(q => `
          <div class="queue-item ${q.is_emergency?'emergency':''}">
            <div class="queue-pos">${q.position}</div>
            <div class="queue-info">
              <div class="queue-name">
                ${q.is_emergency ? '<span style="color:var(--red);font-size:.72rem;font-weight:600">⚠ EMERGENCY &nbsp;</span>' : ''}
                Appt <span class="mono" style="font-size:.78rem">${Fmt.shortId(q.appointment_id)}</span>
              </div>
              <div class="queue-meta">Queue ID: ${Fmt.shortId(q.queue_id)} · ${q.status}</div>
            </div>
            <div class="queue-wait">
              <div>${q.estimated_wait_mins??'—'} min</div>
              <div class="queue-score">score: ${q.priority_score?.toFixed(1)??'—'}</div>
            </div>
            <select class="btn btn-secondary btn-sm" onchange="Pages.updateQueueStatus('${q.queue_id}', this.value)">
              <option value="">Status…</option>
              ${['waiting','called','in_room','done','skipped'].map(s => `<option value="${s}" ${q.status===s?'selected':''}>${s}</option>`).join('')}
            </select>
          </div>`).join('')}
      </div>`;
    } catch(e) { listEl.innerHTML = noData('Failed to load queue'); }
  },

  async nextPatient() {
    const docId = $('#q-doctor-id')?.value, branchId = $('#q-branch-id')?.value;
    if (!docId || !branchId) { Toast.warning('Select', 'Choose a doctor and branch first'); return; }
    try {
      const r = await API.nextPatient(docId, branchId);
      if (r?.message) { Toast.info('Queue', r.message); return; }
      Toast.success('Next Patient', `Appt ${Fmt.shortId(r.appointment_id)} · ${r.urgency}`);
      Pages.loadQueue();
    } catch(e) {}
  },

  async updateQueueStatus(qId, status) {
    if (!status) return;
    try { await API.queueStatus(qId, status); Toast.success('Status updated', status); Pages.loadQueue(); } catch(e) {}
  },

  async openEmergencyModal() {
    Modal.create('em-modal', '⚠ Emergency Override', `
      <p style="color:var(--red);font-size:.875rem;margin-bottom:20px;background:var(--red-dim);padding:10px 14px;border-radius:var(--radius)">
        Immediately moves patient to position #1 with priority score = 999. Use only for genuine emergencies.
      </p>
      <div class="form-group"><label>Queue ID (UUID) *</label>
        <input type="text" id="em-queue-id" placeholder="Queue entry UUID"></div>
      <div class="form-group"><label>Triggered By</label>
        <input type="text" id="em-by" value="${Auth.getUser()?.username||''}" placeholder="Your username"></div>
      <div class="form-group"><label>Reason *</label>
        <textarea id="em-reason" placeholder="Describe the emergency situation…"></textarea></div>`,
    `<button class="btn btn-secondary" onclick="Modal.close('em-modal')">Cancel</button>
     <button class="btn btn-danger" onclick="Pages.doEmergency()">⚠ Override Now</button>`);
  },

  async doEmergency() {
    const data = { queue_id: $('#em-queue-id').value.trim(), triggered_by: $('#em-by').value||null, reason: $('#em-reason').value.trim() };
    if (!data.queue_id || !data.reason) { Toast.error('Validation', 'Queue ID and reason required'); return; }
    try {
      await API.emergencyOverride(data);
      Toast.error('Emergency Override Applied', `Queue ${Fmt.shortId(data.queue_id)} → Position 1`);
      Modal.close('em-modal'); Pages.loadQueue();
    } catch(e) {}
  },

  // ════════════════════════════════════════════════════════════
  // BRANCHES
  // ════════════════════════════════════════════════════════════
  async renderBranches(el) {
    el.innerHTML = `
      <div class="page-header animate-in">
        <div><h2 class="page-title">Branches</h2><div class="page-subtitle">Network locations · K-d Tree routing · Weighted Round Robin</div></div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" onclick="Pages.findNearest()">⊕ Find Nearest</button>
          <button class="btn btn-primary" onclick="Pages.openBranchModal()">+ Add Branch</button>
        </div>
      </div>
      <div class="two-col">
        <div class="card animate-in">
          <div class="card-header"><span class="card-title">Branch Directory</span></div>
          <div class="card-body" id="branches-list">${spinner()}</div>
        </div>
        <div class="card animate-in">
          <div class="card-header"><span class="card-title">Load Balancer</span><span class="badge badge-scheduled">Weighted Round Robin</span></div>
          <div class="card-body" id="load-summary">${spinner()}</div>
        </div>
      </div>`;
    Pages.loadBranches(); Pages.loadBranchSummary();
  },

  async loadBranches() {
    const el = document.getElementById('branches-list');
    if (!el) return;
    try {
      const branches = await API.branches();
      if (!branches?.length) { el.innerHTML = noData('No branches found'); return; }
      el.innerHTML = `<div class="table-wrapper"><table><thead><tr>
        <th>ID</th><th>Name</th><th>City</th><th>Capacity</th><th>Load</th><th>Status</th><th></th>
      </tr></thead><tbody>
        ${branches.map(b => {
          const pct = Math.round((b.current_load||0) * 100);
          const color = pct > 80 ? 'var(--red)' : pct > 60 ? 'var(--amber)' : 'var(--green)';
          return `<tr>
            <td class="mono" style="font-size:.68rem;color:var(--text-muted)">${Fmt.shortId(b.branch_id)}</td>
            <td style="color:var(--text-primary);font-weight:500">${b.branch_name}</td>
            <td>${b.city||'—'}</td>
            <td class="mono">${b.total_capacity}</td>
            <td><div style="display:flex;align-items:center;gap:8px">
              <div class="load-bar-track" style="width:70px;display:inline-block">
                <div class="load-bar-fill" style="width:${pct}%;background:${color}"></div>
              </div>
              <span style="font-size:.72rem;font-family:var(--font-mono);color:${color}">${pct}%</span>
            </div></td>
            <td>${b.is_active ? '<span class="badge badge-completed">Active</span>' : '<span class="badge badge-cancelled">Inactive</span>'}</td>
            <td><button class="btn btn-secondary btn-sm" onclick="Pages.suggestRouting('${b.branch_id}')">Routing</button></td>
          </tr>`;
        }).join('')}
      </tbody></table></div>`;
    } catch(e) { el.innerHTML = noData('Failed to load branches'); }
  },

  async loadBranchSummary() {
    const el = document.getElementById('load-summary');
    if (!el) return;
    try {
      const loads = await API.loadSummary();
      if (!loads?.length) { el.innerHTML = noData('No load data'); return; }
      el.innerHTML = loads.map(b => {
        const pct = b.total_capacity > 0 ? Math.round((b.current_load / b.total_capacity) * 100) : 0;
        const color = b.is_overloaded ? 'var(--red)' : pct > 60 ? 'var(--amber)' : 'var(--green)';
        return `<div class="load-bar-row">
          <div class="load-bar-label" style="font-size:.78rem">
            ${Fmt.shortId(String(b.branch_id))}
            ${b.is_overloaded ? '<span class="badge badge-critical" style="margin-left:6px">Overloaded</span>' : ''}
          </div>
          <div class="load-bar-track"><div class="load-bar-fill" style="width:${pct}%;background:${color}"></div></div>
          <div class="load-bar-pct">${pct}%</div>
        </div>
        <div style="font-size:.72rem;color:var(--text-muted);margin-bottom:10px;font-family:var(--font-mono)">
          ${b.current_load} / ${b.total_capacity} capacity
        </div>`;
      }).join('');
    } catch(e) { el.innerHTML = noData('Load data unavailable'); }
  },

  async suggestRouting(bId) {
    try {
      const r = await API.suggestRouting(bId);
      if (r.redirect_to) Toast.warning('Overflow Redirect', `→ Branch ${Fmt.shortId(r.redirect_to)}: ${r.branch_name||''}`);
      else Toast.success('No Redirect', r.message || 'Branch within capacity');
    } catch(e) {}
  },

  async findNearest() {
    Modal.create('nearest-modal', 'Find Nearest Branch', `
      <p style="font-size:.875rem;color:var(--text-secondary);margin-bottom:16px">Uses K-d Tree (O(log n)) nearest-neighbour search.</p>
      <div class="form-grid">
        <div class="form-group"><label>Latitude</label><input type="number" step="any" id="fn-lat" placeholder="40.7128"></div>
        <div class="form-group"><label>Longitude</label><input type="number" step="any" id="fn-lng" placeholder="-74.0060"></div>
        <div class="form-group"><label>Results (k)</label><input type="number" id="fn-k" value="3" min="1" max="10"></div>
      </div>
      <div id="nearest-results"></div>`,
    `<button class="btn btn-secondary" onclick="Modal.close('nearest-modal')">Close</button>
     <button class="btn btn-primary" onclick="Pages.doNearest()">Search</button>`);
  },

  async doNearest() {
    const lat = parseFloat($('#fn-lat').value), lng = parseFloat($('#fn-lng').value), k = parseInt($('#fn-k').value)||3;
    if (!lat || !lng) { Toast.error('Validation', 'Lat & Lng required'); return; }
    try {
      const r = await API.nearest(lat, lng, k);
      const el = document.getElementById('nearest-results');
      if (!r?.results?.length) { el.innerHTML = noData('None found'); return; }
      el.innerHTML = `<div class="divider"></div>${r.results.map((x,i) => `
        <div class="metric-row">
          <span class="metric-label">#${i+1} Branch ${Fmt.shortId(String(x.branch_id))}</span>
          <span class="metric-value mono" style="font-size:.78rem">${x.lat?.toFixed(4)}, ${x.lng?.toFixed(4)}</span>
        </div>`).join('')}`;
    } catch(e) {}
  },

  async openBranchModal() {
    Modal.create('branch-modal', 'New Branch', `
      <div class="form-grid">
        <div class="form-group"><label>Hospital UUID *</label><input type="text" id="br-hospital" placeholder="Hospital UUID"></div>
        <div class="form-group"><label>Branch Name *</label><input type="text" id="br-name" placeholder="City North Branch"></div>
        <div class="form-group"><label>City</label><input type="text" id="br-city" placeholder="New York"></div>
        <div class="form-group"><label>Total Capacity</label><input type="number" id="br-cap" value="100"></div>
        <div class="form-group"><label>Latitude</label><input type="number" step="any" id="br-lat" placeholder="40.7128"></div>
        <div class="form-group"><label>Longitude</label><input type="number" step="any" id="br-lng" placeholder="-74.0060"></div>
      </div>
      <div class="form-group"><label>Address</label><textarea id="br-addr" rows="2"></textarea></div>`,
    `<button class="btn btn-secondary" onclick="Modal.close('branch-modal')">Cancel</button>
     <button class="btn btn-primary" onclick="Pages.saveBranch()">Create Branch</button>`);
  },

  async saveBranch() {
    const data = { hospital_id: $('#br-hospital').value.trim(), branch_name: $('#br-name').value.trim(),
      city: $('#br-city').value||null, total_capacity: parseInt($('#br-cap').value)||100,
      latitude: parseFloat($('#br-lat').value)||null, longitude: parseFloat($('#br-lng').value)||null,
      address: $('#br-addr').value||null };
    if (!data.hospital_id || !data.branch_name) { Toast.error('Validation', 'Hospital UUID and name required'); return; }
    try {
      await API.createBranch(data);
      Toast.success('Branch created', data.branch_name);
      Modal.close('branch-modal'); Pages.loadBranches(); Pages.loadBranchSummary();
    } catch(e) {}
  },

  // ════════════════════════════════════════════════════════════
  // ANALYTICS
  // ════════════════════════════════════════════════════════════
  async renderAnalytics(el) {
    el.innerHTML = `
      <div class="page-header animate-in">
        <div><h2 class="page-title">Analytics</h2><div class="page-subtitle">Holt-Winters forecasting · Little's Law wait times · Doctor performance</div></div>
      </div>
      <div class="three-col animate-in" id="analytics-summary" style="margin-bottom:24px">${spinner()}</div>
      <div class="two-col" style="margin-bottom:24px">
        <div class="card animate-in">
          <div class="card-header"><span class="card-title">Peak Hour Forecast</span><span class="badge badge-scheduled">Holt-Winters</span></div>
          <div class="card-body">
            <div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap">
              <div class="form-group" style="margin:0;flex:1;min-width:140px"><label>Branch UUID</label>
                <input type="text" id="pf-branch" placeholder="Branch UUID"></div>
              <div class="form-group" style="margin:0;flex:1;min-width:140px"><label>Department UUID</label>
                <input type="text" id="pf-dept" placeholder="Department UUID"></div>
              <div style="display:flex;align-items:flex-end">
                <button class="btn btn-secondary btn-sm" onclick="Pages.loadPeakForecast()">Forecast</button>
              </div>
            </div>
            <div id="peak-result">${noData('Enter UUIDs and click Forecast')}</div>
          </div>
        </div>
        <div class="card animate-in">
          <div class="card-header"><span class="card-title">Doctor Performance</span></div>
          <div class="card-body">
            <div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap">
              <div class="form-group" style="margin:0;flex:1;min-width:140px"><label>Doctor UUID</label>
                <input type="text" id="dp-doc" placeholder="Doctor UUID"></div>
              <div class="form-group" style="margin:0;width:80px"><label>Days</label>
                <input type="number" id="dp-days" value="30" min="1" max="365"></div>
              <div style="display:flex;align-items:flex-end">
                <button class="btn btn-secondary btn-sm" onclick="Pages.loadDoctorPerf()">Load</button>
              </div>
            </div>
            <div id="dp-result">${noData('Enter Doctor UUID and click Load')}</div>
          </div>
        </div>
      </div>
      <div class="card animate-in">
        <div class="card-header"><span class="card-title">Wait Time Trends</span><span class="badge badge-scheduled">Little's Law</span></div>
        <div class="card-body">
          <div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap">
            <div class="form-group" style="margin:0;flex:1;min-width:160px"><label>Department UUID</label>
              <input type="text" id="wt-dept" placeholder="Department UUID"></div>
            <div class="form-group" style="margin:0;width:80px"><label>Days</label>
              <input type="number" id="wt-days" value="14" min="1" max="90"></div>
            <div style="display:flex;align-items:flex-end">
              <button class="btn btn-secondary btn-sm" onclick="Pages.loadWaitTrends()">Load</button>
            </div>
          </div>
          <div id="wt-result">${noData('Enter Department UUID and click Load')}</div>
        </div>
      </div>`;
    Pages.loadAnalyticsSummary();
  },

  async loadAnalyticsSummary() {
    const el = document.getElementById('analytics-summary');
    if (!el) return;
    try {
      const s = await API.summary();
      if (!s) return;
      el.innerHTML = `
        <div class="stat-card" style="--accent:var(--gold)"><div class="stat-icon" style="background:var(--gold-dim);color:var(--gold)">◷</div><div class="stat-value">${s.appointments_today}</div><div class="stat-label">Today</div></div>
        <div class="stat-card" style="--accent:var(--green)"><div class="stat-icon" style="background:var(--green-dim);color:var(--green)">✓</div><div class="stat-value">${s.total_completed}</div><div class="stat-label">Completed</div></div>
        <div class="stat-card" style="--accent:var(--red)"><div class="stat-icon" style="background:var(--red-dim);color:var(--red)">⚠</div><div class="stat-value">${s.critical_cases}</div><div class="stat-label">Critical</div></div>`;
    } catch(e) { el.innerHTML = ''; }
  },

  async loadPeakForecast() {
    const el = document.getElementById('peak-result');
    const bId = $('#pf-branch').value.trim(), dId = $('#pf-dept').value.trim();
    if (!bId || !dId) { Toast.error('Validation', 'Both UUIDs required'); return; }
    el.innerHTML = spinner();
    try {
      const r = await API.peakForecast(bId, dId);
      if (!r || r.message) { el.innerHTML = `<div class="empty-state"><div class="empty-state-text">${r?.message||'No data'}</div></div>`; return; }
      el.innerHTML = `
        <div class="metric-row"><span class="metric-label">Data Points</span><span class="metric-value">${r.data_points}</span></div>
        ${r.peak_hours?.length ? `<div class="metric-row"><span class="metric-label">Peak Hours</span><span class="metric-value">${r.peak_hours.map(h=>h+':00').join(', ')}</span></div>` : ''}
        <div style="margin-top:16px">
          <div style="font-family:var(--font-mono);font-size:.7rem;color:var(--text-muted);margin-bottom:8px">24-HOUR DEMAND FORECAST</div>
          <div style="display:flex;gap:2px;align-items:flex-end;height:64px">
            ${(r.forecast_24h||[]).slice(0,24).map((v,i) => {
              const max = Math.max(...(r.forecast_24h||[1]));
              const h = max > 0 ? Math.round((v/max)*54)+6 : 6;
              const isPeak = r.peak_hours?.includes(i);
              return `<div style="flex:1;height:${h}px;background:${isPeak?'var(--gold)':'var(--bg-hover)'};border-radius:2px 2px 0 0;transition:height .4s" title="Hour ${i}: ${v?.toFixed(1)}"></div>`;
            }).join('')}
          </div>
          <div style="display:flex;justify-content:space-between;font-family:var(--font-mono);font-size:.62rem;color:var(--text-muted);margin-top:4px">
            <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:00</span>
          </div>
        </div>`;
    } catch(e) { el.innerHTML = noData('Forecast unavailable'); }
  },

  async loadDoctorPerf() {
    const el = document.getElementById('dp-result');
    const docId = $('#dp-doc').value.trim(), days = parseInt($('#dp-days').value)||30;
    if (!docId) { Toast.error('Validation', 'Doctor UUID required'); return; }
    el.innerHTML = spinner();
    try {
      const records = await API.doctorPerf(docId, days);
      if (!records?.length) { el.innerHTML = noData('No performance data'); return; }
      const latest = records[records.length - 1];
      el.innerHTML = `
        <div class="metric-row"><span class="metric-label">Latest Date</span><span class="metric-value">${Fmt.date(latest.date)}</span></div>
        <div class="metric-row"><span class="metric-label">Total Appointments</span><span class="metric-value mono">${latest.total_appointments}</span></div>
        <div class="metric-row"><span class="metric-label">Completed</span><span class="metric-value mono" style="color:var(--green)">${latest.completed_count}</span></div>
        <div class="metric-row"><span class="metric-label">No-shows</span><span class="metric-value mono" style="color:var(--red)">${latest.no_show_count}</span></div>
        <div class="metric-row"><span class="metric-label">Avg Consult</span><span class="metric-value mono">${latest.avg_consult_mins?.toFixed(1)||'—'} min</span></div>
        <div class="metric-row"><span class="metric-label">Utilization</span><span class="metric-value mono">${latest.utilization_pct?.toFixed(1)||'—'}%</span></div>
        <div class="progress-bar"><div class="progress-fill" style="width:${latest.utilization_pct||0}%"></div></div>`;
    } catch(e) { el.innerHTML = noData('Data unavailable'); }
  },

  async loadWaitTrends() {
    const el = document.getElementById('wt-result');
    const deptId = $('#wt-dept').value.trim(), days = parseInt($('#wt-days').value)||14;
    if (!deptId) { Toast.error('Validation', 'Department UUID required'); return; }
    el.innerHTML = spinner();
    try {
      const trends = await API.waitTimeTrends(deptId, days);
      if (!trends?.length) { el.innerHTML = noData('No trend data'); return; }
      el.innerHTML = `<div class="table-wrapper"><table><thead><tr>
        <th>Date</th><th>Hour</th><th>Avg Wait</th><th>Min</th><th>Max</th><th>Samples</th>
      </tr></thead><tbody>
        ${trends.map(t => `<tr>
          <td class="mono" style="font-size:.78rem">${t.date}</td>
          <td class="mono">${t.hour}:00</td>
          <td class="mono" style="color:var(--gold)">${t.avg_wait_mins?.toFixed(1)} min</td>
          <td class="mono" style="color:var(--green)">${t.min_wait_mins?.toFixed(1)}</td>
          <td class="mono" style="color:var(--red)">${t.max_wait_mins?.toFixed(1)}</td>
          <td class="mono" style="color:var(--text-muted)">${t.sample_count}</td>
        </tr>`).join('')}
      </tbody></table></div>`;
    } catch(e) { el.innerHTML = noData('Trend data unavailable'); }
  },
};

// ── Init ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  Router.go(Auth.isLoggedIn() ? 'dashboard' : 'login');
});
